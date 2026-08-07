package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const (
	localSlug  = "acme/payments"
	localSHA   = "abc123def456"
	localImage = "payments-api:1.4.2" // the ArtifactName in testdata/trivy-sample.json
)

// estateEvents is the topology that puts a scanned image on an internet -> crown-jewel
// route. It is the same wiring `ingestreal` uses against a live stack, so this exercises
// the shape the product actually produces rather than one invented for the test:
//
//	load balancer (internet) --exposes--> image --affects--> CVE --exploits--> secret
//
// The image node itself is NOT declared here. It arrives with the scanner report, which
// is the whole point: the report is what carries the commit into the graph.
func estateEvents() []ontology.Event {
	imageID := ontology.NewID(ontology.LabelImage, localImage)
	cveID := ontology.NewID(ontology.LabelCVE, "CVE-2021-44228")
	lbID := ontology.NewID(ontology.LabelLoadBalancer, "edge-alb")
	jewelID := ontology.NewID(ontology.LabelSecret, "secrets-vault")

	return []ontology.Event{{
		Source:     "test-estate",
		Kind:       ontology.KindAsset,
		ObservedAt: time.Now().UTC(),
		Nodes: []ontology.Node{
			{ID: lbID, Label: ontology.LabelLoadBalancer, Name: "edge-alb",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: jewelID, Label: ontology.LabelSecret, Name: "secrets-vault",
				Properties: map[string]any{ontology.PropCrownJewel: true, ontology.PropCrownJewelBasis: "tagged:operator"}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeExposes, From: lbID, To: imageID, ExploitProbability: 0.9},
			{Type: ontology.EdgeExploits, From: cveID, To: jewelID, ExploitProbability: 0.9},
		},
	}}
}

// writeEstate materialises the estate as the events JSON `-estate` reads.
func writeEstate(t *testing.T, events []ontology.Event) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "estate.json")
	b, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func trivySampleSpec(t *testing.T) reportSpec {
	t.Helper()
	p, err := filepath.Abs("../../testdata/trivy-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the trivy fixture moved: %v", err)
	}
	return reportSpec{source: "trivy", path: p}
}

func baseOpts(t *testing.T) localOpts {
	t.Helper()
	return localOpts{
		slug: localSlug, sha: localSHA, repository: localSlug,
		estate: writeEstate(t, estateEvents()),
	}
}

// The headline case: with no engine deployed anywhere, the runner reads the estate,
// ingests this pull request's scan, and finds that the change sits on a route to a
// sensitive asset.
func TestLocalModeFindsThePathThroughTheCommit(t *testing.T) {
	o := baseOpts(t)
	o.reports = []reportSpec{trivySampleSpec(t)}

	v, err := localVerdict(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Analysed {
		t.Fatal("the scanned image did not reach the graph, so the gate would report UNKNOWN for a commit it did analyse")
	}
	if v.CriticalPaths == 0 {
		t.Fatalf("no critical path attributed to the commit: %+v", v)
	}
	var named bool
	for _, p := range v.Paths {
		for _, n := range p.Nodes {
			if n.Name == localImage {
				named = true
			}
		}
		if p.Priority <= 0 {
			t.Errorf("path %s has priority %v - Prioritize did not run, so the gate ranks differently from the dashboard", p.ID, p.Priority)
		}
	}
	if !named {
		t.Errorf("the scanned image is not on the reported route: %+v", v.Paths)
	}
	if v.AnalysedAt == "" {
		t.Error("no analysedAt, so the verdict is not comparable with the server's")
	}
}

// THE property that justifies local mode existing at all. It must be a different way to
// OBTAIN the graph, not a second engine with its own opinions - so on the same events it
// has to produce what the analyzer service produces, in the same order, with the same
// triage priority.
//
// Verified to bite: removing analyzer.Prioritize from localVerdict fails this test with
// "local priority 0, service 39.2". That mutation compiles and still returns paths, so
// nothing else would have caught a gate that ranks a pull request differently from the
// dashboard looking at the same estate.
func TestLocalModeAgreesWithTheAnalyzerService(t *testing.T) {
	ctx := context.Background()
	o := baseOpts(t)
	o.reports = []reportSpec{trivySampleSpec(t)}

	local, err := localVerdict(ctx, o)
	if err != nil {
		t.Fatal(err)
	}

	// The same events, through the service that runs inside the server.
	store := memory.New()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return store, nil })
	if err != nil {
		t.Fatal(err)
	}
	norm := normalization.New(mgr)
	events := estateEvents()
	reportEvents, err := o.parseReports()
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range append(reportEvents, events...) {
		if err := norm.Handle(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}

	runCtx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)
	svc := analyzer.NewService(mgr, 5*time.Millisecond, nil)
	go func() { _ = svc.Run(runCtx) }()

	deadline := time.Now().Add(10 * time.Second)
	var served []analyzer.AttackPath
	for {
		served = svc.Latest(graph.DefaultTenant)
		if len(served) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the analyzer service produced no paths for an estate local mode found paths in")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Compare only the paths the commit is on, which is what a gate reports.
	var want []analyzer.AttackPath
	for _, p := range served {
		for _, n := range p.Nodes {
			if ontology.StampedWith(n.Properties, localSlug, localSHA) {
				want = append(want, p)
				break
			}
		}
	}

	if len(local.Paths) != len(want) {
		t.Fatalf("local mode found %d paths through the commit, the service found %d", len(local.Paths), len(want))
	}
	for i := range want {
		if local.Paths[i].ID != want[i].ID {
			t.Errorf("path %d: local %q, service %q - the two modes order paths differently", i, local.Paths[i].ID, want[i].ID)
		}
		if local.Paths[i].Priority != want[i].Priority {
			t.Errorf("path %d (%s): local priority %v, service %v", i, want[i].ID, local.Paths[i].Priority, want[i].Priority)
		}
		if local.Paths[i].Score != want[i].Score {
			t.Errorf("path %d (%s): local score %v, service %v", i, want[i].ID, local.Paths[i].Score, want[i].Score)
		}
	}
}

// standaloneEstate is a complete internet -> crown-jewel route that has nothing to do
// with the commit under test: no scanned image anywhere in it.
func standaloneEstate() []ontology.Event {
	lbID := ontology.NewID(ontology.LabelLoadBalancer, "legacy-alb")
	vmID := ontology.NewID(ontology.LabelVirtualMachine, "legacy-box")
	jewelID := ontology.NewID(ontology.LabelSecret, "secrets-vault")
	return []ontology.Event{{
		Source:     "test-estate",
		Kind:       ontology.KindAsset,
		ObservedAt: time.Now().UTC(),
		Nodes: []ontology.Node{
			{ID: lbID, Label: ontology.LabelLoadBalancer, Name: "legacy-alb",
				Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: vmID, Label: ontology.LabelVirtualMachine, Name: "legacy-box"},
			{ID: jewelID, Label: ontology.LabelSecret, Name: "secrets-vault",
				Properties: map[string]any{ontology.PropCrownJewel: true, ontology.PropCrownJewelBasis: "tagged:operator"}},
		},
		Edges: []ontology.Edge{
			{Type: ontology.EdgeExposes, From: lbID, To: vmID, ExploitProbability: 0.9},
			{Type: ontology.EdgeExploits, From: vmID, To: jewelID, ExploitProbability: 0.9},
		},
	}}
}

// The distinction the whole gate rests on, in its hardest form: the estate is readable,
// the engine found real attack paths in it, and none of them is this commit's. That is
// UNKNOWN - nobody analysed this change - and it must NOT read as clean just because the
// count of paths attributable to the commit happens to be zero.
func TestLocalModeReportsUnknownWhenNoReportCarriesTheCommit(t *testing.T) {
	o := baseOpts(t)
	o.estate = writeEstate(t, standaloneEstate())

	v, err := localVerdict(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if v.Analysed {
		t.Fatal("reported as analysed with no scanner report ingested, which a gate would read as clean")
	}
	if v.CriticalPaths != 0 {
		t.Errorf("criticalPaths = %d for a commit nothing carries", v.CriticalPaths)
	}
}

// The boundary of what local mode is willing to claim. Without an estate there are no
// attack paths, only a flat list of findings - so it must refuse, loudly. Returning a
// clean verdict here would be the worst possible failure: a green check that means
// "I had nothing to reason about".
func TestLocalModeRefusesToAnswerWithoutAnEstate(t *testing.T) {
	_, err := localVerdict(context.Background(), localOpts{slug: localSlug, sha: localSHA})
	if err == nil {
		t.Fatal("answered with no estate at all")
	}
	if !strings.Contains(err.Error(), "-aws-region") || !strings.Contains(err.Error(), "-estate") {
		t.Errorf("the error does not say how to supply an estate: %v", err)
	}
}

// An estate file that parses but describes nothing is the same mistake wearing different
// clothes: credentials that read no resources, or a region with nothing in it.
func TestLocalModeRefusesAnEmptyEstate(t *testing.T) {
	o := baseOpts(t)
	o.estate = writeEstate(t, nil)
	if _, err := localVerdict(context.Background(), o); err == nil {
		t.Fatal("accepted an estate with no events")
	}
}

// A misspelled -source must fail before an AWS collection is paid for, and must say what
// the valid names are rather than leaving the operator to guess.
func TestUnknownSourceIsRejectedUpFront(t *testing.T) {
	var r reportFlag
	if err := r.Set("trivvy=report.json"); err != nil {
		t.Fatal(err)
	}
	_, err := r.resolveSources("trivy")
	if err == nil {
		t.Fatal("accepted a source no collector handles")
	}
	if !strings.Contains(err.Error(), "trivvy") || !strings.Contains(err.Error(), "semgrep") {
		t.Errorf("the error names neither the mistake nor the alternatives: %v", err)
	}
}

func TestReportFlagParsing(t *testing.T) {
	var r reportFlag
	for _, v := range []string{"trivy=t.json", "s.json", "semgrep=sem.json"} {
		if err := r.Set(v); err != nil {
			t.Fatalf("Set(%q): %v", v, err)
		}
	}
	got, err := r.resolveSources("trivy")
	if err != nil {
		t.Fatal(err)
	}
	want := []reportSpec{
		{source: "trivy", path: "t.json"},
		{source: "trivy", path: "s.json"}, // bare path inherits -source
		{source: "semgrep", path: "sem.json"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d specs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("spec %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	var bad reportFlag
	for _, v := range []string{"", "=x.json", "trivy="} {
		if err := bad.Set(v); err == nil {
			t.Errorf("Set(%q) was accepted", v)
		}
	}
}

// An estate that points at an asset no report supplied must fail with a message that
// says what to do. Silently dropping the edge would be the dangerous alternative: it
// removes the link that made the commit reachable and turns a blocked build green.
func TestLocalModeExplainsAnEstateReferringToAMissingAsset(t *testing.T) {
	o := baseOpts(t) // this estate points at the scanned image
	_, err := localVerdict(context.Background(), o)
	if err == nil {
		t.Fatal("accepted an estate whose edge had no endpoint, so the route was silently incomplete")
	}
	if !strings.Contains(err.Error(), "-report") {
		t.Errorf("the error does not say how to fix it: %v", err)
	}
}

// Estate sources add up. Almost nobody's environment is one cloud region, so the file is
// the escape hatch for what the connector cannot read - another provider, on-prem, the CI
// provenance linking an image to where it runs. Letting one source silently override the
// other would drop half the environment and then answer confidently about the remainder,
// and for a reachability question a route that leaves the part that WAS read looks
// exactly like no route at all.
//
// This was a real defect: the first version picked one source with a switch, so passing
// both silently discarded the live collection.
func TestEstateSourcesAddUpRatherThanOverride(t *testing.T) {
	fromCloud := standaloneEstate() // 3 nodes, a complete route of its own
	o := localOpts{
		slug: localSlug, sha: localSHA,
		estate:       writeEstate(t, estateEvents()), // 2 nodes
		collectAWSFn: func(context.Context) ([]ontology.Event, error) { return fromCloud, nil },
	}

	got, err := o.collectEstate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(estateEvents())+len(fromCloud) {
		t.Fatalf("collectEstate returned %d events, want %d - one source overrode the other",
			len(got), len(estateEvents())+len(fromCloud))
	}

	var sawFile, sawCloud bool
	for _, ev := range got {
		for _, n := range ev.Nodes {
			switch n.Name {
			case "edge-alb":
				sawFile = true
			case "legacy-alb":
				sawCloud = true
			}
		}
	}
	if !sawFile {
		t.Error("the -estate file's assets are missing from the merged estate")
	}
	if !sawCloud {
		t.Error("the live collection's assets are missing from the merged estate")
	}
}

// A failure reading the live account must stop the run. Continuing on whatever the file
// happened to contain would grade the commit against a fraction of the environment and
// call the result clean.
func TestLocalModeStopsWhenTheLiveCollectionFails(t *testing.T) {
	o := localOpts{
		slug: localSlug, sha: localSHA,
		estate:       writeEstate(t, estateEvents()),
		collectAWSFn: func(context.Context) ([]ontology.Event, error) { return nil, errors.New("AccessDenied") },
	}
	if _, err := o.collectEstate(context.Background()); err == nil {
		t.Fatal("carried on after failing to read the live account")
	}
}

// Forward references are normal here, not exceptional: the report introduces the image,
// the cloud connector describes the roles, and a supplement links the two - so whichever
// is applied first points at something that does not exist yet. Publishing an ordering
// rule and letting anyone who gets it wrong watch the run die on an edge is not a fix.
//
// This was found against a real AWS account: a supplement referring to a live IAM role
// died because the file was read before the connector ran.
func TestEventsApplyRegardlessOfOrder(t *testing.T) {
	ctx := context.Background()
	forward := append(parseTrivyForTest(t), estateEvents()...)

	reversed := make([]ontology.Event, len(forward))
	for i, ev := range forward {
		reversed[len(forward)-1-i] = ev
	}

	for name, events := range map[string][]ontology.Event{"forward": forward, "reversed": reversed} {
		t.Run(name, func(t *testing.T) {
			store := memory.New()
			mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return store, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := applyEvents(ctx, normalization.New(mgr), events); err != nil {
				t.Fatalf("applying in %s order failed: %v", name, err)
			}
			snap, err := store.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			paths := analyzer.CriticalPathsVia(ctx, store, snap, localMaxHops, false)
			if len(paths) == 0 {
				t.Fatalf("%s order built a graph with no attack path - an edge was lost", name)
			}
		})
	}
}

// A reference that nothing anywhere describes is a genuine hole, not a forward reference,
// and no ordering would have saved it. It must stop the run: the edge that would be
// dropped is exactly the one that made the commit reachable, and losing it reports clean.
func TestATrulyDanglingReferenceStillFails(t *testing.T) {
	ctx := context.Background()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	if err != nil {
		t.Fatal(err)
	}
	// The estate alone: its edges point at an image no report ever supplies.
	if err := applyEvents(ctx, normalization.New(mgr), estateEvents()); err == nil {
		t.Fatal("accepted an edge whose endpoint nothing described, silently losing the route")
	}
}

func parseTrivyForTest(t *testing.T) []ontology.Event {
	t.Helper()
	o := localOpts{slug: localSlug, sha: localSHA, repository: localSlug, reports: []reportSpec{trivySampleSpec(t)}}
	events, err := o.parseReports()
	if err != nil {
		t.Fatal(err)
	}
	return events
}
