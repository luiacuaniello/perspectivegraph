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
// are warm), but must NOT fire external side-effects (PR comments) — that is the
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
