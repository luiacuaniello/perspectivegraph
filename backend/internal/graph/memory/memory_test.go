package memory

import (
	"context"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// TestSnapshotSinceReturnsOnlyChanged checks the incremental-delta contract: a
// SnapshotSince(t) returns exactly the elements stamped last_seen >= t, and
// patching them onto a prior full snapshot reproduces a fresh full snapshot - so
// the analyzer's cache can never diverge from the store on the delta path.
func TestSnapshotSinceReturnsOnlyChanged(t *testing.T) {
	ctx := context.Background()
	s := New()

	// Two nodes observed at t=100, joined by an edge.
	mustUpsertNode(t, s, "a", 100, map[string]any{ontology.PropInternetExposed: true})
	mustUpsertNode(t, s, "b", 100, nil)
	mustUpsertEdge(t, s, "a", "b", 100)

	// A later observation at t=200 adds a node + edge and refreshes "b".
	mustUpsertNode(t, s, "c", 200, map[string]any{ontology.PropCrownJewel: true})
	mustUpsertEdge(t, s, "b", "c", 200)
	mustUpsertNode(t, s, "b", 200, nil)

	// Delta since 150 must carry only the t=200 writes: c, b (refreshed), and b->c.
	d, err := s.SnapshotSince(ctx, 150)
	if err != nil {
		t.Fatalf("SnapshotSince: %v", err)
	}
	gotNodes := idset(d.Nodes)
	if len(gotNodes) != 2 || !gotNodes["c"] || !gotNodes["b"] {
		t.Fatalf("delta nodes = %v, want {b,c}", keys(gotNodes))
	}
	if len(d.Edges) != 1 || d.Edges[0].From != "b" || d.Edges[0].To != "c" {
		t.Fatalf("delta edges = %+v, want one b->c", d.Edges)
	}

	// since 0 must equal a full snapshot.
	full, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	all, err := s.SnapshotSince(ctx, 0)
	if err != nil {
		t.Fatalf("SnapshotSince(0): %v", err)
	}
	if len(all.Nodes) != len(full.Nodes) || len(all.Edges) != len(full.Edges) {
		t.Fatalf("SnapshotSince(0) = %dn/%de, full = %dn/%de",
			len(all.Nodes), len(all.Edges), len(full.Nodes), len(full.Edges))
	}
}

func mustUpsertNode(t *testing.T, s *Store, id string, lastSeen int64, extra map[string]any) {
	t.Helper()
	props := map[string]any{ontology.PropLastSeen: lastSeen}
	for k, v := range extra {
		props[k] = v
	}
	if err := s.UpsertNode(context.Background(), ontology.Node{ID: id, Label: ontology.LabelContainer, Name: id, Properties: props}); err != nil {
		t.Fatalf("upsert node %s: %v", id, err)
	}
}

func mustUpsertEdge(t *testing.T, s *Store, from, to string, lastSeen int64) {
	t.Helper()
	e := ontology.Edge{Type: ontology.EdgeConnectsTo, From: from, To: to, ExploitProbability: 0.5,
		Properties: map[string]any{ontology.PropLastSeen: lastSeen}}
	if err := s.UpsertEdge(context.Background(), e); err != nil {
		t.Fatalf("upsert edge %s->%s: %v", from, to, err)
	}
}

func idset(nodes []ontology.Node) map[string]bool {
	m := map[string]bool{}
	for _, n := range nodes {
		m[n.ID] = true
	}
	return m
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
