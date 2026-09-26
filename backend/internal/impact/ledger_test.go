package impact

import (
	"context"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const tenant = "acme"

// live is a running engine in miniature: a graph the change is ingested into for real,
// and the analyzer passes a ledger watches.
type live struct {
	t      *testing.T
	store  *memory.Store
	norm   *normalization.Normalizer
	ledger *Ledger
}

func newLive(t *testing.T, base graph.Snapshot) *live {
	t.Helper()
	ctx := context.Background()
	store := memory.New()
	must(t, store.UpsertBatch(ctx, base.Nodes, base.Edges))
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return store, nil })
	must(t, err)
	return &live{t: t, store: store, norm: normalization.New(mgr), ledger: NewLedger()}
}

// pass runs one analyzer pass as the service does and shows it to the ledger.
func (l *live) pass() []analyzer.AttackPath {
	l.t.Helper()
	snap, err := l.store.Snapshot(context.Background())
	must(l.t, err)
	paths := analyzer.FindCriticalPaths(snap)
	analyzer.Prioritize(paths)
	l.ledger.ObservePass(tenant, snap, paths)
	return paths
}

func (l *live) ingest(events []ontology.Event) {
	l.t.Helper()
	for _, ev := range events {
		must(l.t, l.norm.Handle(context.Background(), ev))
	}
}

// judged counts the paths through the commit that count against it, and those that do
// not - what the engine's commit status reports.
func (l *live) judged(paths []analyzer.AttackPath) (counted int, preexisting int, changes []Change) {
	for _, p := range paths {
		through := false
		for _, n := range p.Nodes {
			if ontology.StampedWith(n.Properties, slug, sha) {
				through = true
			}
		}
		if !through {
			continue
		}
		if v := l.ledger.Judge(tenant, slug, sha, p); v.Counts {
			counted++
			changes = append(changes, v.Change)
		} else {
			preexisting++
		}
	}
	return counted, preexisting, changes
}

// The engine's commit status and the merge gate must give a change the same answer. The
// gate compares a copy of the estate before and after the change; the engine, which only
// ever sees the graph after, compares with the pass before the commit arrived. On the
// same change, the two must count the same routes - or a pull request is green in the
// gate's check and red in the engine's, and a team trusts neither.
func TestTheEngineAgreesWithTheGate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change []ontology.Event
	}{
		{"rescan", scan(nil, nil)},
		{"worsen", scan(
			[]ontology.Node{node("cve-new", ontology.LabelCVE, nil)},
			[]ontology.Edge{edge("lib", "cve-new", ontology.EdgeAffects, 0.9), edge("cve-new", "admin", ontology.EdgeExploits, 0.9)},
		)},
		{"introduce", scan(
			[]ontology.Node{node("cve-new", ontology.LabelCVE, nil)},
			[]ontology.Edge{edge("lib", "cve-new", ontology.EdgeAffects, 0.5), edge("cve-new", "ledger", ontology.EdgeExploits, 0.9)},
		)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := estate(t)
			gate := evaluate(t, base, tc.change)

			eng := newLive(t, base)
			eng.pass() // the estate before the change
			eng.ingest(tc.change)
			counted, preexisting, changes := eng.judged(eng.pass())

			if counted != len(gate.Blocking) || preexisting != gate.Preexisting {
				t.Fatalf("engine counts %d (%d preexisting), gate %d (%d preexisting)",
					counted, preexisting, len(gate.Blocking), gate.Preexisting)
			}
			for i, ch := range changes {
				if ch != gate.Blocking[i].Change {
					t.Errorf("route %d: engine says %s, gate %s", i, ch, gate.Blocking[i].Change)
				}
			}
		})
	}
}

// With no "before" - the engine restarted after the change landed - every route through
// the commit counts, as the gate counts it when the engine already holds the commit.
// The two stay in agreement there too.
func TestWithoutABeforeTheEngineCountsAsTheGateDoesForARecordedCommit(t *testing.T) {
	base := estate(t)
	change := scan(nil, nil)

	eng := newLive(t, base)
	eng.ingest(change) // landed before this engine was watching
	counted, preexisting, changes := eng.judged(eng.pass())

	after, err := eng.store.Snapshot(context.Background())
	must(t, err)
	gate := evaluate(t, after, change) // the gate re-run on a commit the engine holds
	if !gate.Recorded {
		t.Fatal("the gate should see the commit as recorded")
	}
	if counted != 1 || preexisting != 0 || changes[0] != Recorded {
		t.Fatalf("engine: counted %d preexisting %d %v, want the one route counted as recorded", counted, preexisting, changes)
	}
	if counted != len(gate.Blocking) {
		t.Errorf("engine counts %d, gate %d", counted, len(gate.Blocking))
	}
}

// The first pass after the engine starts is the "before" of everything that arrives
// later - an empty one included. A ledger that only started watching once there were
// routes would take the first commit for one that was already there and count its
// routes by the per-commit rule; here, they are the commit's own.
func TestAPassWithNoRoutesIsABefore(t *testing.T) {
	eng := newLive(t, graph.Snapshot{})
	if paths := eng.pass(); len(paths) != 0 {
		t.Fatalf("empty graph has %d paths", len(paths))
	}
	base := estate(t)
	must(t, eng.store.UpsertBatch(context.Background(), base.Nodes, base.Edges))
	eng.ingest(scan(nil, nil))
	counted, _, changes := eng.judged(eng.pass())
	if counted != 1 || changes[0] != Introduced {
		t.Fatalf("counted %d %v, want the route introduced", counted, changes)
	}
}

// A route that appears through the commit's assets later, with no pull request arriving
// on it - here a change from outside any pull request - still counts against the commit:
// it is real, and it runs through the change. It counts as Later, which does not claim
// the change opened it.
func TestARouteThatAppearsLaterThroughTheCommitCounts(t *testing.T) {
	eng := newLive(t, estate(t))
	eng.pass()
	eng.ingest(scan(nil, nil))
	if counted, _, _ := eng.judged(eng.pass()); counted != 0 {
		t.Fatalf("the rescan counts %d", counted)
	}
	// Outside any pull request: the library now reaches the ledger bucket.
	eng.ingest([]ontology.Event{{Source: "custodian", Kind: ontology.KindFinding,
		Nodes: []ontology.Node{node("cve-late", ontology.LabelCVE, nil)},
		Edges: []ontology.Edge{edge("lib", "cve-late", ontology.EdgeAffects, 0.5), edge("cve-late", "ledger", ontology.EdgeExploits, 0.9)}}})
	counted, preexisting, changes := eng.judged(eng.pass())
	if counted != 1 || changes[0] != Later || preexisting != 1 {
		t.Fatalf("counted %d %v preexisting %d, want the late route counted as later and the old one not", counted, changes, preexisting)
	}
}

// A route another pull request opens through the commit's assets is that request's, not
// the commit's. Found live: a second load balancer in front of a rescanned image turned
// the rescan's status red, and its comment said "this change opens it".
func TestARouteAnotherPullRequestOpensIsThatRequests(t *testing.T) {
	eng := newLive(t, estate(t))
	eng.pass()
	eng.ingest(scan(nil, nil)) // the rescan, commit c0ffee
	eng.pass()
	lb2 := ontology.Node{ID: "lb2", Label: ontology.LabelLoadBalancer, Name: "lb2", Properties: map[string]any{
		ontology.PropInternetExposed: true, ontology.PropRepoSlug: "acme/infra", ontology.PropCommitSHA: "beef"}}
	eng.ingest([]ontology.Event{{Source: "k8s", Kind: ontology.KindAsset,
		Nodes: []ontology.Node{lb2},
		Edges: []ontology.Edge{edge("lb2", img, ontology.EdgeExposes, 0.9)}}})
	paths := eng.pass()

	counted, preexisting, _ := eng.judged(paths)
	if counted != 0 || preexisting != 2 {
		t.Fatalf("the rescan: counted %d preexisting %d, want nothing counted", counted, preexisting)
	}
	opened := 0
	for _, p := range paths {
		if v := eng.ledger.Judge(tenant, "acme/infra", "beef", p); v.Counts && v.Change == Introduced {
			opened++
		}
	}
	if opened != 1 {
		t.Errorf("the load balancer's change opened %d route(s), want 1", opened)
	}
}

// A commit that leaves the graph - a newer push restamped its assets - is forgotten, and
// if it comes back it arrives again, against the routes of the pass before it did.
func TestACommitThatLeavesAndReturnsArrivesAgain(t *testing.T) {
	l := NewLedger()
	imgNode := ontology.Node{ID: "img", Properties: stamp}
	route := analyzer.AttackPath{Score: 0.5, Nodes: []ontology.Node{{ID: "lb"}, imgNode, {ID: "admin"}}}
	stamped := graph.Snapshot{Nodes: []ontology.Node{imgNode}}
	l.ObservePass(tenant, graph.Snapshot{}, nil)
	l.ObservePass(tenant, stamped, []analyzer.AttackPath{route})
	if v := l.Judge(tenant, slug, sha, route); v.Change != Introduced {
		t.Fatalf("first arrival: %+v, want introduced", v)
	}
	l.ObservePass(tenant, graph.Snapshot{}, []analyzer.AttackPath{route}) // restamped away
	l.ObservePass(tenant, stamped, []analyzer.AttackPath{route})          // and back
	if v := l.Judge(tenant, slug, sha, route); v.Counts {
		t.Fatalf("second arrival found the route there: %+v, want preexisting", v)
	}
}

// Tenants are separate estates: a commit arriving in one says nothing about another, and
// in a tenant the ledger never saw it arrive in, the per-commit rule decides.
func TestTheLedgerKeepsTenantsApart(t *testing.T) {
	l := NewLedger()
	route := pathOf("lb", "admin", 0.5)
	l.ObservePass("a", graph.Snapshot{}, []analyzer.AttackPath{route})
	l.ObservePass("a", graph.Snapshot{Nodes: []ontology.Node{{ID: "img", Properties: stamp}}}, []analyzer.AttackPath{route})
	if v := l.Judge("a", slug, sha, route); v.Counts {
		t.Fatalf("tenant a: %+v, want preexisting", v)
	}
	if v := l.Judge("b", slug, sha, route); !v.Counts || v.Change != Recorded {
		t.Fatalf("tenant b: %+v, want counted by the per-commit rule", v)
	}
}

// No ledger is the per-commit rule, PR_ATTRIBUTION=commit: every route through the
// commit counts.
func TestANilLedgerCountsEveryRoute(t *testing.T) {
	var l *Ledger
	if v := l.Judge(tenant, slug, sha, pathOf("lb", "admin", 0.5)); !v.Counts || v.Change != Recorded {
		t.Fatalf("%+v, want counted by the per-commit rule", v)
	}
	if l.Enabled() {
		t.Error("a nil ledger reports itself enabled")
	}
}

func pathOf(from, to string, score float64) analyzer.AttackPath {
	return analyzer.AttackPath{Score: score, Nodes: []ontology.Node{{ID: from}, {ID: to}}}
}

// A route a commit made likelier counts while it stays likelier than it was: fixing what
// made it so - the new CVE patched, elsewhere - takes it off the commit, as the gate would
// no longer count it.
func TestAWorsenedRouteBackToItsOldOddsStopsCounting(t *testing.T) {
	l := NewLedger()
	imgNode := ontology.Node{ID: "img", Properties: stamp}
	at := func(score float64) analyzer.AttackPath {
		return analyzer.AttackPath{Score: score, Nodes: []ontology.Node{{ID: "lb"}, imgNode, {ID: "admin"}}}
	}
	l.ObservePass(tenant, graph.Snapshot{}, []analyzer.AttackPath{at(0.5)})
	l.ObservePass(tenant, graph.Snapshot{Nodes: []ontology.Node{imgNode}}, []analyzer.AttackPath{at(0.8)})
	if v := l.Judge(tenant, slug, sha, at(0.8)); !v.Counts || v.Change != Worsened || v.PreviousScore != 0.5 {
		t.Fatalf("worsened on arrival: %+v", v)
	}
	l.ObservePass(tenant, graph.Snapshot{Nodes: []ontology.Node{imgNode}}, []analyzer.AttackPath{at(0.5)})
	if v := l.Judge(tenant, slug, sha, at(0.5)); v.Counts {
		t.Fatalf("back to its old odds, still counted: %+v", v)
	}
}
