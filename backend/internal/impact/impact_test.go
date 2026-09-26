package impact

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/k8s"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const slug, sha = "acme/payments", "c0ffee"

var stamp = map[string]any{ontology.PropRepoSlug: slug, ontology.PropCommitSHA: sha}

// img is the image's id as the normalizer writes it - keyed on the image reference - so
// the scan's copy lands on the estate's, as it does for real.
var img = ontology.NewID(ontology.LabelImage, "app:1.0")

func node(id string, label ontology.Label, props map[string]any) ontology.Node {
	return ontology.Node{ID: id, Label: label, Name: id, Properties: props}
}

func edge(from, to string, t ontology.EdgeType, p float64) ontology.Edge {
	return ontology.Edge{Type: t, From: from, To: to, ExploitProbability: p}
}

// estate: an internet load balancer in front of a container that runs an image whose
// library carries one weak CVE into the admin role - the best route to the role (the
// container's own role binding is weaker), so it runs through the image.
func estate(t *testing.T) graph.Snapshot {
	t.Helper()
	store := memory.New()
	must(t, store.UpsertBatch(context.Background(), []ontology.Node{
		node("lb", ontology.LabelLoadBalancer, map[string]any{ontology.PropInternetExposed: true}),
		node("web", ontology.LabelContainer, nil),
		{ID: img, Label: ontology.LabelImage, Name: "app:1.0"},
		node("lib", ontology.LabelLibrary, nil),
		node("cve-old", ontology.LabelCVE, nil),
		node("admin", ontology.LabelIAMRole, map[string]any{ontology.PropCrownJewel: true}),
		node("ledger", ontology.LabelBucket, map[string]any{ontology.PropCrownJewel: true}),
	}, []ontology.Edge{
		edge("lb", "web", ontology.EdgeExposes, 0.9),
		edge("web", "admin", ontology.EdgeAssumes, 0.1),
		edge("web", img, ontology.EdgeHosts, 0.9),
		edge(img, "lib", ontology.EdgeDependsOn, 0.95),
		edge("lib", "cve-old", ontology.EdgeAffects, 0.3),
		edge("cve-old", "admin", ontology.EdgeExploits, 0.8),
	}))
	snap, err := store.Snapshot(context.Background())
	must(t, err)
	return snap
}

// scan is the pull request's image scan: the image and its library, stamped with the
// commit, plus whatever else the change brings.
func scan(nodes []ontology.Node, edges []ontology.Edge) []ontology.Event {
	base := []ontology.Node{
		{ID: img, Label: ontology.LabelImage, Name: "app:1.0", Properties: stamp},
		node("lib", ontology.LabelLibrary, nil),
		node("cve-old", ontology.LabelCVE, nil),
	}
	baseEdges := []ontology.Edge{
		edge(img, "lib", ontology.EdgeDependsOn, 0.95),
		edge("lib", "cve-old", ontology.EdgeAffects, 0.3),
	}
	return []ontology.Event{{Source: "trivy", Kind: ontology.KindFinding,
		Nodes: append(base, nodes...), Edges: append(baseEdges, edges...)}}
}

func evaluate(t *testing.T, base graph.Snapshot, change []ontology.Event) Result {
	t.Helper()
	res, err := Evaluate(context.Background(), Input{Base: base, Change: change, Slug: slug, SHA: sha})
	must(t, err)
	return res
}

// A rescan of an image already in the estate opens nothing. The per-commit gate counted
// the route through it - the commit is stamped on the image - and blocked a change that
// added no risk.
func TestARescanOfTheSameImageOpensNothing(t *testing.T) {
	res := evaluate(t, estate(t), scan(nil, nil))
	if !res.Analysed || !res.Reachable {
		t.Fatalf("analysed=%v reachable=%v, want both", res.Analysed, res.Reachable)
	}
	if len(res.Blocking) != 0 {
		t.Fatalf("a rescan blocks on %+v", res.Blocking)
	}
	if res.Preexisting != 1 {
		t.Errorf("preexisting = %d, want the one route through the image", res.Preexisting)
	}
}

// A new, likelier CVE on the same route makes the route worse: it counts, with the
// score it had before.
func TestANewCVEOnAnExistingRouteWorsensIt(t *testing.T) {
	res := evaluate(t, estate(t), scan(
		[]ontology.Node{node("cve-new", ontology.LabelCVE, nil)},
		[]ontology.Edge{edge("lib", "cve-new", ontology.EdgeAffects, 0.9), edge("cve-new", "admin", ontology.EdgeExploits, 0.9)},
	))
	if len(res.Blocking) != 1 || res.Blocking[0].Change != Worsened {
		t.Fatalf("blocking = %+v, want one worsened route", res.Blocking)
	}
	p := res.Blocking[0]
	if p.PreviousScore >= p.Score || p.PreviousScore <= 0 {
		t.Errorf("worsened from %.4f to %.4f", p.PreviousScore, p.Score)
	}
	if res.Preexisting != 0 {
		t.Errorf("the worsened route is not also preexisting: %d", res.Preexisting)
	}
}

// A CVE that reaches a sensitive asset nothing reached before opens a route.
func TestAChangeThatReachesANewAssetIntroducesARoute(t *testing.T) {
	res := evaluate(t, estate(t), scan(
		[]ontology.Node{node("cve-new", ontology.LabelCVE, nil)},
		[]ontology.Edge{edge("lib", "cve-new", ontology.EdgeAffects, 0.5), edge("cve-new", "ledger", ontology.EdgeExploits, 0.9)},
	))
	var introduced []Path
	for _, p := range res.Blocking {
		if p.Change == Introduced {
			introduced = append(introduced, p)
		}
	}
	if len(introduced) != 1 || introduced[0].Target().ID != "ledger" {
		t.Fatalf("blocking = %+v, want the new route to the ledger", res.Blocking)
	}
}

// When the estate already carries the commit - persisted by an earlier run, or posted to
// the webhook by another step - the comparison is against a graph that contains the
// change, and it cannot tell its routes from the ones that were there. It then counts
// them as the per-commit gate would: blocking a change it might have passed, never
// passing one it would have blocked.
func TestAnEstateThatAlreadyCarriesTheCommitIsJudgedPerCommit(t *testing.T) {
	base := estate(t)
	for i, n := range base.Nodes {
		if n.ID == img {
			base.Nodes[i].Properties = stamp
		}
	}
	res := evaluate(t, base, scan(nil, nil))
	if !res.Recorded {
		t.Fatal("the estate carried the commit, and the result does not say so")
	}
	if len(res.Blocking) != 1 || res.Blocking[0].Change != Recorded {
		t.Fatalf("blocking = %+v, want the route through the commit counted as recorded", res.Blocking)
	}
}

// A report stamped with another commit was not this change: nothing analysed, which
// the gate reports as UNKNOWN rather than clean.
func TestAReportOfAnotherCommitIsNotAnalysed(t *testing.T) {
	change := scan(nil, nil)
	change[0].Nodes[0].Properties = map[string]any{ontology.PropRepoSlug: slug, ontology.PropCommitSHA: "other"}
	res := evaluate(t, estate(t), change)
	if res.Analysed {
		t.Error("a report of another commit counted as this one's")
	}
}

// An image that nothing runs is analysed but not reachable - usually a naming mismatch
// between the scan and the workload, which the gate points out.
func TestAnImageNothingRunsIsNotReachable(t *testing.T) {
	res := evaluate(t, estate(t), []ontology.Event{{Source: "trivy", Kind: ontology.KindFinding,
		Nodes: []ontology.Node{{ID: "orphan", Label: ontology.LabelImage, Name: "orphan:1.0", Properties: stamp}}}})
	if !res.Analysed || res.Reachable || len(res.Blocking) != 0 {
		t.Errorf("analysed=%v reachable=%v blocking=%d, want true false 0", res.Analysed, res.Reachable, len(res.Blocking))
	}
}

// The estate is read, never written: the snapshot handed in - which may share its maps
// with a live in-memory store - comes out exactly as it went in.
func TestTheEstateIsNeverWritten(t *testing.T) {
	live := memory.New()
	ctx := context.Background()
	must(t, live.UpsertBatch(ctx, estate(t).Nodes, estate(t).Edges))
	base, err := live.Snapshot(ctx)
	must(t, err)
	want := cloneSnapshot(base)
	_ = evaluate(t, base, scan(
		[]ontology.Node{node("cve-new", ontology.LabelCVE, nil)},
		[]ontology.Edge{edge("lib", "cve-new", ontology.EdgeAffects, 0.9), edge("cve-new", "ledger", ontology.EdgeExploits, 0.9)},
	))
	if !reflect.DeepEqual(base, want) {
		t.Error("the snapshot handed in was modified")
	}
	after, err := live.Snapshot(ctx)
	must(t, err)
	if len(after.Nodes) != len(want.Nodes) || len(after.Edges) != len(want.Edges) {
		t.Errorf("the live store changed: %d nodes %d edges, was %d %d", len(after.Nodes), len(after.Edges), len(want.Nodes), len(want.Edges))
	}
	for _, n := range after.Nodes {
		if ontology.StampedWith(n.Properties, slug, sha) {
			t.Errorf("node %s in the live store carries the commit", n.ID)
		}
	}
}

// The demo lab's case, with the real Kubernetes collector: a pull request re-renders
// every manifest of a deployment, so the commit lands on every asset of it. Judged per
// commit, every route through the deployment counted against the change; judged by what
// the change adds, an unchanged render opens nothing.
func TestReRenderingUnchangedManifestsOpensNothing(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/k8s-sample.json")
	must(t, err)
	parse := func(opts ingestion.Options) []ontology.Event {
		evs, err := k8s.New().Parse(bytes.NewReader(raw), opts)
		must(t, err)
		return evs
	}
	base := normalized(t, parse(ingestion.Options{}))
	if len(analyzer.FindCriticalPaths(base)) == 0 {
		t.Fatal("setup: the sample estate has no critical path to compare")
	}
	res := evaluate(t, base, parse(ingestion.Options{RepoSlug: slug, CommitSHA: sha}))
	if !res.Analysed || res.Preexisting == 0 {
		t.Fatalf("analysed=%v preexisting=%d: the render touches the deployment's routes", res.Analysed, res.Preexisting)
	}
	if len(res.Blocking) != 0 {
		t.Errorf("an unchanged render blocks on %d route(s): %+v", len(res.Blocking), res.Blocking)
	}
}

func normalized(t *testing.T, events []ontology.Event) graph.Snapshot {
	t.Helper()
	store := memory.New()
	mgr, err := graph.NewManager(context.Background(), func(context.Context, string) (graph.Store, error) { return store, nil })
	must(t, err)
	norm := normalization.New(mgr)
	for _, ev := range events {
		must(t, norm.Handle(context.Background(), ev))
	}
	snap, err := store.Snapshot(context.Background())
	must(t, err)
	return snap
}

func cloneSnapshot(s graph.Snapshot) graph.Snapshot {
	out := graph.Snapshot{Nodes: append([]ontology.Node(nil), s.Nodes...), Edges: append([]ontology.Edge(nil), s.Edges...)}
	for i := range out.Nodes {
		out.Nodes[i].Properties = cloneMap(s.Nodes[i].Properties)
	}
	for i := range out.Edges {
		out.Edges[i].Properties = cloneMap(s.Edges[i].Properties)
	}
	return out
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// An estate whose workload points at an image only the scan describes: the link waits,
// and must still be there when the scan arrives - a snapshot of the estate would have
// dropped it, and the image would have looked unreachable.
func TestAnEdgeWaitingForTheChangeLandsInTheCopy(t *testing.T) {
	base := estate(t)
	var keep []ontology.Edge
	var link ontology.Edge
	var nodes []ontology.Node
	for _, e := range base.Edges {
		if e.To == img {
			link = e
			continue
		}
		if e.From != img {
			keep = append(keep, e)
		}
	}
	for _, n := range base.Nodes {
		if n.ID != img {
			nodes = append(nodes, n)
		}
	}
	res, err := Evaluate(context.Background(), Input{
		Base: graph.Snapshot{Nodes: nodes, Edges: keep}, BasePending: []ontology.Edge{link},
		Change: scan(nil, nil), Slug: slug, SHA: sha,
	})
	must(t, err)
	if !res.Reachable || res.Waiting != 0 {
		t.Fatalf("reachable=%v waiting=%d: the workload's link to the scanned image did not land", res.Reachable, res.Waiting)
	}
	// Without the scan the route through the image did not exist, so relative to this
	// estate the scan introduces it.
	if len(res.Blocking) != 1 || res.Blocking[0].Change != Worsened && res.Blocking[0].Change != Introduced {
		t.Errorf("blocking = %+v", res.Blocking)
	}
}
