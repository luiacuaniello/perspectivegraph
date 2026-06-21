package normalization

import (
	"context"
	"testing"

	"github.com/aegisgraph/aegisgraph/internal/graph/memory"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

func TestNormalizeImageRef(t *testing.T) {
	cases := map[string]string{
		"123.dkr.ecr.us-east-1.amazonaws.com/payments-api:1.4.2": "payments-api:1.4.2",
		"docker.io/library/nginx:1.25":                           "library/nginx:1.25",
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
	store := memory.New()
	n := New(store)
	ctx := context.Background()

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
	store := memory.New()
	n := New(store)
	ctx := context.Background()

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
