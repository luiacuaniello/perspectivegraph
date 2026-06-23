package analyzer

import (
	"context"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type recordingSink struct{ calls int }

func (r *recordingSink) OnCriticalPaths(context.Context, []AttackPath) { r.calls++ }

type fakeLeader struct{ leader bool }

func (f fakeLeader) IsLeader(context.Context) bool { return f.leader }

func seedOnePath(t *testing.T, store graph.Store) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(store.UpsertNode(ctx, ontology.Node{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-lb",
		Properties: map[string]any{ontology.PropInternetExposed: true}}))
	must(store.UpsertNode(ctx, ontology.Node{ID: "role", Label: ontology.LabelIAMRole, Name: "admin",
		Properties: map[string]any{ontology.PropCrownJewel: true}}))
	must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeExposes, From: "lb", To: "role", ExploitProbability: 0.9}))
}

// A non-leader replica must still compute & cache attack paths (so its API reads
// are warm), but must NOT fire external side-effects (PR comments) - that is the
// leader's job, at most once across the fleet.
func TestSideEffectsGatedByLeadership(t *testing.T) {
	ctx := context.Background()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	if err != nil {
		t.Fatal(err)
	}
	store, err := mgr.For(ctx, graph.DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	seedOnePath(t, store)

	// Follower: computes the path (warm cache) but the sink stays silent.
	follower := &recordingSink{}
	svc := NewService(mgr, time.Minute, follower).WithLeader(fakeLeader{leader: false})
	svc.runTenant(ctx, graph.DefaultTenant)
	if got := len(svc.Latest(graph.DefaultTenant)); got != 1 {
		t.Fatalf("follower should still compute 1 path for its own API, got %d", got)
	}
	if follower.calls != 0 {
		t.Errorf("follower must not post PR comments, sink fired %d times", follower.calls)
	}

	// Leader: the sink fires once.
	lead := &recordingSink{}
	svc2 := NewService(mgr, time.Minute, lead).WithLeader(fakeLeader{leader: true})
	svc2.runTenant(ctx, graph.DefaultTenant)
	if lead.calls != 1 {
		t.Errorf("leader should post once, sink fired %d times", lead.calls)
	}
}

func TestAlwaysLeaderIsDefault(t *testing.T) {
	ctx := context.Background()
	mgr, _ := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	store, _ := mgr.For(ctx, graph.DefaultTenant)
	seedOnePath(t, store)

	sink := &recordingSink{}
	NewService(mgr, time.Minute, sink).runTenant(ctx, graph.DefaultTenant) // no WithLeader
	if sink.calls != 1 {
		t.Errorf("default (always-leader) should fire the sink once, got %d", sink.calls)
	}
}

// seedStampedPath writes a 2-node internet→jewel path with an explicit last_seen
// stamp, so the incremental delta path (which filters on last_seen) can be tested
// deterministically.
func seedStampedPath(t *testing.T, store graph.Store, suffix string, lastSeen int64) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	props := func(extra map[string]any) map[string]any {
		m := map[string]any{ontology.PropLastSeen: lastSeen}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	must(store.UpsertNode(ctx, ontology.Node{ID: "lb" + suffix, Label: ontology.LabelLoadBalancer, Name: "lb" + suffix,
		Properties: props(map[string]any{ontology.PropInternetExposed: true})}))
	must(store.UpsertNode(ctx, ontology.Node{ID: "jewel" + suffix, Label: ontology.LabelDatabase, Name: "jewel" + suffix,
		Properties: props(map[string]any{ontology.PropCrownJewel: true})}))
	must(store.UpsertEdge(ctx, ontology.Edge{Type: ontology.EdgeExposes, From: "lb" + suffix, To: "jewel" + suffix,
		ExploitProbability: 0.9, Properties: props(nil)}))
}

// TestIncrementalMatchesFullSnapshot is the safety contract for incremental
// snapshotting: an analyzer that patches a cached snapshot from per-pass deltas
// must report the same attack paths as one that re-reads the whole graph. We seed
// path A (in the past), run a full first pass, add path B (stamped ahead of the
// watermark so the delta fetches it), run a second (delta) pass, and assert the
// resulting path set equals a control analyzer that read everything in one shot.
func TestIncrementalMatchesFullSnapshot(t *testing.T) {
	ctx := context.Background()
	now := time.Now().Unix()
	past, future := now-3600, now+3600

	mkSvc := func(incremental bool) *Service {
		mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
		if err != nil {
			t.Fatal(err)
		}
		return NewService(mgr, time.Minute, nil).WithIncremental(incremental)
	}

	// Incremental: full pass on A, then a delta pass that must pick up B.
	inc := mkSvc(true)
	incStore, _ := inc.manager.For(ctx, graph.DefaultTenant)
	seedStampedPath(t, incStore, "A", past)
	inc.runTenant(ctx, graph.DefaultTenant)
	if got := len(inc.Latest(graph.DefaultTenant)); got != 1 {
		t.Fatalf("after full pass want 1 path, got %d", got)
	}
	seedStampedPath(t, incStore, "B", future)
	inc.runTenant(ctx, graph.DefaultTenant) // delta pass

	// Control: a single full read of the same two paths.
	full := mkSvc(false)
	fullStore, _ := full.manager.For(ctx, graph.DefaultTenant)
	seedStampedPath(t, fullStore, "A", past)
	seedStampedPath(t, fullStore, "B", future)
	full.runTenant(ctx, graph.DefaultTenant)

	want := pathScores(full.Latest(graph.DefaultTenant))
	got := pathScores(inc.Latest(graph.DefaultTenant))
	if len(got) != 2 {
		t.Fatalf("incremental analyzer should report 2 paths after the delta, got %d", len(got))
	}
	for id, ws := range want {
		if gs, ok := got[id]; !ok || gs != ws {
			t.Fatalf("path %s: incremental score %v (ok=%v) != full score %v", id, gs, ok, ws)
		}
	}
}

func pathScores(paths []AttackPath) map[string]float64 {
	m := make(map[string]float64, len(paths))
	for _, p := range paths {
		m[p.ID] = p.Score
	}
	return m
}
