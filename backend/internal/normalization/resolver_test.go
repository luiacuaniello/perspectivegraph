package normalization

import (
	"context"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// managerFor returns a manager whose every tenant resolves to the shared store,
// so a test can assert against it directly.
func managerFor(ctx context.Context, t *testing.T, store graph.Store) *graph.Manager {
	t.Helper()
	m, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return store, nil })
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNormalizeImageRef(t *testing.T) {
	cases := map[string]string{
		"123.dkr.ecr.us-east-1.amazonaws.com/payments-api:1.4.2": "payments-api:1.4.2",
		"docker.io/library/nginx:1.25":                           "nginx:1.25",
		"library/nginx:1.25":                                     "nginx:1.25",
		"nginx:1.25":                                             "nginx:1.25",
		"localhost/app:dev":                                      "app:dev",
		"registry:5000/app:dev":                                  "app:dev",
		"payments-api:1.4.2":                                     "payments-api:1.4.2",
	}
	for in, want := range cases {
		if got := NormalizeImageRef(in); got != want {
			t.Errorf("NormalizeImageRef(%q) = %q, want %q", in, got, want)
		}
	}
}

// An ECR-qualified image and a bare repo:tag must converge on one Image node.
func TestImageDedupAcrossRegistries(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	n := New(managerFor(ctx, t, store))

	// Trivy-style: bare name.
	_ = n.Handle(ctx, ontology.Event{Nodes: []ontology.Node{
		{ID: ontology.NewID(ontology.LabelImage, "payments-api:1.4.2"), Label: ontology.LabelImage, Name: "payments-api:1.4.2"},
	}})
	// Cloud-style: same image via ECR URI (different raw id/name).
	ecr := "123.dkr.ecr.us-east-1.amazonaws.com/payments-api:1.4.2"
	_ = n.Handle(ctx, ontology.Event{Nodes: []ontology.Node{
		{ID: ontology.NewID(ontology.LabelImage, ecr), Label: ontology.LabelImage, Name: ecr},
	}})

	snap, _ := store.Snapshot(ctx)
	images := 0
	for _, node := range snap.Nodes {
		if node.Label == ontology.LabelImage {
			images++
		}
	}
	if images != 1 {
		t.Fatalf("expected the two image refs to dedup to 1 node, got %d", images)
	}
}

// A runtime Container that declares its image gets a HOSTS edge to the Image
// node, stitching runtime context to the scanner's findings.
func TestInferHostsEdgeFromImageRef(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	n := New(managerFor(ctx, t, store))

	containerID := ontology.NewID(ontology.LabelContainer, "payments")
	_ = n.Handle(ctx, ontology.Event{Nodes: []ontology.Node{{
		ID:         containerID,
		Label:      ontology.LabelContainer,
		Name:       "payments",
		Properties: map[string]any{ontology.PropImageRef: "registry.example.com/payments-api:1.4.2"},
	}}})

	snap, _ := store.Snapshot(ctx)
	wantImg := ontology.NewID(ontology.LabelImage, "payments-api:1.4.2")
	var hosts bool
	for _, e := range snap.Edges {
		if e.Type == ontology.EdgeHosts && e.From == containerID && e.To == wantImg {
			hosts = true
		}
	}
	if !hosts {
		t.Fatalf("expected inferred HOSTS edge %s -> %s; edges=%v", containerID, wantImg, snap.Edges)
	}
}

func TestInferCrownJewels(t *testing.T) {
	ev := inferCrownJewels(ontology.Event{Nodes: []ontology.Node{
		{ID: "Database:customer-pii-db", Label: ontology.LabelDatabase, Name: "customer-pii-db"},
		{ID: "Bucket:public-assets", Label: ontology.LabelBucket, Name: "public-assets"},
		{ID: "Database:already", Label: ontology.LabelDatabase, Name: "billing-store",
			Properties: map[string]any{ontology.PropCrownJewel: false}}, // explicit tag wins
		{ID: "Container:payments", Label: ontology.LabelContainer, Name: "payments-secret"}, // not a data store
	}})
	byID := map[string]ontology.Node{}
	for _, n := range ev.Nodes {
		byID[n.ID] = n
	}
	if n := byID["Database:customer-pii-db"]; !n.Bool(ontology.PropCrownJewel) ||
		n.Properties[ontology.PropCrownJewelBasis] != "inferred:pii" {
		t.Errorf("PII-named DB should be inferred a crown jewel: %+v", n.Properties)
	}
	if byID["Bucket:public-assets"].Bool(ontology.PropCrownJewel) {
		t.Error("a benign bucket must not be inferred a crown jewel")
	}
	if byID["Database:already"].Bool(ontology.PropCrownJewel) {
		t.Error("an explicit crown_jewel=false tag must not be overridden")
	}
	if byID["Container:payments"].Bool(ontology.PropCrownJewel) {
		t.Error("only data stores are inferred, not containers")
	}
}

// imageMatch must grade the container→image join by how precisely the ref pins
// the image: a digest is an exact identity, a tag is strong, a bare name is a
// weak correlation an analyst should distrust.
func TestImageMatchConfidence(t *testing.T) {
	cases := []struct {
		ref        string
		wantMethod string
		wantConf   float64
	}{
		{"nginx@sha256:" + strings.Repeat("a", 64), "digest", 1.0},
		{"registry.example.com/payments-api:1.4.2", "tag", 0.85},
		{"payments-api", "name", 0.6},
		{"docker.io/library/nginx", "name", 0.6},
	}
	for _, tc := range cases {
		_, method, conf := imageMatch(tc.ref)
		if method != tc.wantMethod || conf != tc.wantConf {
			t.Errorf("imageMatch(%q) = (%q, %v), want (%q, %v)", tc.ref, method, conf, tc.wantMethod, tc.wantConf)
		}
	}
}

// The inferred Image node and HOSTS edge must carry the resolution provenance so
// the API/UI can flag a heuristic join, and a weak join must weight lower than a
// strong one.
func TestInferHostsCarriesResolutionProvenance(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	n := New(managerFor(ctx, t, store))

	containerID := ontology.NewID(ontology.LabelContainer, "web")
	// Bare name → weak "name" join.
	_ = n.Handle(ctx, ontology.Event{Nodes: []ontology.Node{{
		ID:         containerID,
		Label:      ontology.LabelContainer,
		Name:       "web",
		Properties: map[string]any{ontology.PropImageRef: "internal-web"},
	}}})

	snap, _ := store.Snapshot(ctx)
	var img *ontology.Node
	for i := range snap.Nodes {
		if snap.Nodes[i].Label == ontology.LabelImage {
			img = &snap.Nodes[i]
		}
	}
	if img == nil {
		t.Fatal("expected an inferred Image node")
	}
	if got := img.Properties[ontology.PropResolutionMethod]; got != "name" {
		t.Errorf("image resolution_method = %v, want name", got)
	}
	if got, _ := img.Properties[ontology.PropResolutionConfidence].(float64); got != 0.6 {
		t.Errorf("image resolution_confidence = %v, want 0.6", got)
	}
	if got := img.Properties[ontology.PropResolutionAlias]; got != "internal-web" {
		t.Errorf("image resolution_alias = %v, want internal-web", got)
	}
	for _, e := range snap.Edges {
		if e.Type == ontology.EdgeHosts {
			// 0.6 + 0.35*0.6 = 0.81
			if e.ExploitProbability >= 0.95 {
				t.Errorf("weak join HOSTS probability = %v, want < 0.95", e.ExploitProbability)
			}
		}
	}
}

func TestClassifyCrownJewels(t *testing.T) {
	ev := ontology.Event{Nodes: []ontology.Node{
		{ID: "b1", Label: ontology.LabelBucket, Name: "exports", Properties: map[string]any{ontology.PropClassification: "PII"}},
		{ID: "b2", Label: ontology.LabelBucket, Name: "logs", Properties: map[string]any{ontology.PropClassification: "internal"}},
		{ID: "b3", Label: ontology.LabelBucket, Name: "tagged", Properties: map[string]any{ontology.PropClassification: "pci", ontology.PropCrownJewel: true}},
		{ID: "b4", Label: ontology.LabelDatabase, Name: "macie-db", Properties: map[string]any{ontology.PropClassification: "phi", ontology.PropCrownJewelBasis: "classified:macie:phi"}},
	}}
	out := classifyCrownJewels(ev)
	get := func(id string) ontology.Node {
		for _, n := range out.Nodes {
			if n.ID == id {
				return n
			}
		}
		return ontology.Node{}
	}

	// PII (case-insensitive) → crown jewel with basis classified:pii.
	if get("b1").Properties[ontology.PropCrownJewel] != true || get("b1").Properties[ontology.PropCrownJewelBasis] != "classified:pii" {
		t.Errorf("b1 = %+v, want crown jewel classified:pii", get("b1").Properties)
	}
	// A non-sensitive classification is not a jewel.
	if _, ok := get("b2").Properties[ontology.PropCrownJewel]; ok {
		t.Error("non-sensitive classification (internal) must not become a crown jewel")
	}
	// An explicit owner tag is never overwritten by a classification basis.
	if get("b3").Properties[ontology.PropCrownJewelBasis] == "classified:pci" {
		t.Error("explicit crown_jewel tag should not be overwritten")
	}
	// A richer basis already set by the source is preserved.
	if get("b4").Properties[ontology.PropCrownJewel] != true || get("b4").Properties[ontology.PropCrownJewelBasis] != "classified:macie:phi" {
		t.Errorf("b4 should be a jewel keeping its richer basis, got %+v", get("b4").Properties)
	}
}

// TestScrubSensitive checks the C5 data-hygiene pass: a secret captured in a
// finding's property value is redacted (and the node stamped), while identifiers
// the graph joins on are left exactly as they were.
func TestScrubSensitive(t *testing.T) {
	ev := ontology.Event{
		Nodes: []ontology.Node{
			{ID: "w1", Label: ontology.LabelWeakness, Name: "hardcoded-credential",
				Properties: map[string]any{
					"message": "hardcoded AKIAIOSFODNN7EXAMPLE in src/config.py:7",
					"sha":     "deadbeefcafebabe1234567890abcdef12345678",
				}},
			{ID: "img", Label: ontology.LabelImage, Name: "acme/payments-api:1.4.2",
				Properties: map[string]any{"digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}},
		},
	}

	out := scrubSensitive(ev)
	w1 := out.Nodes[0].Properties
	if msg, _ := w1["message"].(string); strings.Contains(msg, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived scrubbing: %q", msg)
	}
	if msg, _ := w1["message"].(string); !strings.Contains(msg, "src/config.py:7") {
		t.Errorf("finding context lost: %q", msg)
	}
	if w1[ontology.PropSecretsScrubbed] != true {
		t.Error("scrubbed node should be stamped secrets_scrubbed")
	}
	// A git SHA must NOT look like a secret (it's a correlation key).
	if w1["sha"] != "deadbeefcafebabe1234567890abcdef12345678" {
		t.Errorf("commit sha was mangled: %v", w1["sha"])
	}
	// An image digest must survive untouched, and a clean node is not stamped.
	img := out.Nodes[1].Properties
	if img["digest"] != "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Errorf("image digest was mangled: %v", img["digest"])
	}
	if _, stamped := img[ontology.PropSecretsScrubbed]; stamped {
		t.Error("a node with no secret should not be stamped")
	}
}
