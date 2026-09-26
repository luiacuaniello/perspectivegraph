package analyzer

import (
	"context"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

type recordingSink struct {
	calls   int
	tenants []string
	paths   []int
}

func (r *recordingSink) OnCriticalPaths(_ context.Context, tenant string, paths []AttackPath) {
	r.calls++
	r.tenants = append(r.tenants, tenant)
	r.paths = append(r.paths, len(paths))
}

type recordingObserver struct {
	passes int
	nodes  []int
}

func (r *recordingObserver) ObservePass(_ string, snap graph.Snapshot, _ []AttackPath) {
	r.passes++
	r.nodes = append(r.nodes, len(snap.Nodes))
}

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

// The observer keeps state built from the sequence of passes - what each commit found
// when it arrived - so it must see every pass on every replica: a follower that became
// leader with an empty observer would judge every commit as if it had just arrived.
func TestObserverSeesEveryPassOnEveryReplica(t *testing.T) {
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

	obs, sink := &recordingObserver{}, &recordingSink{}
	NewService(mgr, time.Minute, sink).WithLeader(fakeLeader{leader: false}).WithPassObserver(obs).
		runTenant(ctx, graph.DefaultTenant)
	if obs.passes != 1 || obs.nodes[0] != 2 {
		t.Errorf("a follower's observer saw %d pass(es) %v, want 1 pass of the 2-node graph", obs.passes, obs.nodes)
	}
	if sink.calls != 0 {
		t.Errorf("a follower's sink fired %d times", sink.calls)
	}
}

// A status that went red on a route has to hear that the route is gone. The sink used to
// be skipped on a pass with no paths, so when the last route closed, the check stayed red.
// And it has to know whose pass it is: its state is per tenant, and a pass of one tenant
// must not clear another's.
func TestSinkHearsTheTenantAndAPassWithNoPaths(t *testing.T) {
	ctx := context.Background()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	if err != nil {
		t.Fatal(err)
	}
	store, err := mgr.For(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	seedOnePath(t, store)

	sink := &recordingSink{}
	svc := NewService(mgr, time.Minute, sink)
	svc.runTenant(ctx, "acme")
	// The role stops being a sensitive asset, so the route stops being a critical path.
	if err := store.UpsertNode(ctx, ontology.Node{ID: "role", Label: ontology.LabelIAMRole, Name: "admin",
		Properties: map[string]any{ontology.PropCrownJewel: false}}); err != nil {
		t.Fatal(err)
	}
	svc.runTenant(ctx, "acme")

	if sink.calls != 2 || sink.paths[0] != 1 || sink.paths[1] != 0 {
		t.Fatalf("sink heard %d pass(es) with %v path(s), want 2 passes: 1 path, then none", sink.calls, sink.paths)
	}
	for _, tn := range sink.tenants {
		if tn != "acme" {
			t.Errorf("sink heard tenant %q, want acme", tn)
		}
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

// A delta carries no deletions, so an incremental analyzer that only patched its cache
// would keep reporting a route through an asset a complete snapshot has retracted - on
// every replica, until the periodic full read. The removal epoch makes it rebuild.
func TestIncrementalAnalyzerSeesARetractedAsset(t *testing.T) {
	ctx := context.Background()
	mgr, err := graph.NewManager(ctx, func(context.Context, string) (graph.Store, error) { return memory.New(), nil })
	if err != nil {
		t.Fatal(err)
	}
	store, _ := mgr.For(ctx, graph.DefaultTenant)
	taken := time.Now().Add(-time.Minute)
	for _, id := range []string{"a", "b"} {
		if err := graph.ApplyEvent(ctx, store, ontology.Event{Source: "cloudnet", ObservedAt: taken,
			Snapshot: &ontology.Snapshot{Scope: "aws:1/eu-west-1", Taken: taken},
			Nodes: []ontology.Node{
				{ID: "lb-" + id, Label: ontology.LabelLoadBalancer, Name: "lb-" + id, Properties: map[string]any{ontology.PropInternetExposed: true}},
				{ID: "db-" + id, Label: ontology.LabelDatabase, Name: "db-" + id, Properties: map[string]any{ontology.PropCrownJewel: true}}},
			Edges: []ontology.Edge{{Type: ontology.EdgeExposes, From: "lb-" + id, To: "db-" + id, ExploitProbability: 0.9}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewService(mgr, time.Minute, nil).WithIncremental(true)
	svc.runTenant(ctx, graph.DefaultTenant)
	if got := len(svc.Latest(graph.DefaultTenant)); got != 2 {
		t.Fatalf("first pass: %d paths, want 2", got)
	}

	// The next pull lists only "a": "b"'s load balancer and database are retracted.
	now := time.Now()
	if err := graph.ApplyEvent(ctx, store, ontology.Event{Source: "cloudnet", ObservedAt: now,
		Snapshot: &ontology.Snapshot{Scope: "aws:1/eu-west-1", Taken: now},
		Nodes: []ontology.Node{
			{ID: "lb-a", Label: ontology.LabelLoadBalancer, Name: "lb-a", Properties: map[string]any{ontology.PropInternetExposed: true}},
			{ID: "db-a", Label: ontology.LabelDatabase, Name: "db-a", Properties: map[string]any{ontology.PropCrownJewel: true}}},
		Edges: []ontology.Edge{{Type: ontology.EdgeExposes, From: "lb-a", To: "db-a", ExploitProbability: 0.9}},
	}); err != nil {
		t.Fatal(err)
	}
	if stats, err := store.Sweep(ctx, "cloudnet", "aws:1/eu-west-1", now); err != nil || stats.Nodes != 2 {
		t.Fatalf("sweep: %+v %v", stats, err)
	}
	svc.runTenant(ctx, graph.DefaultTenant)
	if got := len(svc.Latest(graph.DefaultTenant)); got != 1 {
		t.Fatalf("after the retraction: %d paths, want 1 - the cache kept the retracted route", got)
	}
}
