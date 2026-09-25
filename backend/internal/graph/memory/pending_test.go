package memory

import (
	"context"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// A parked edge waits graph.PendingEdgeTTL for its endpoint and is dropped after that.
// Retrying it when an unrelated write names its OTHER end must not restart the wait, or
// an edge to an asset that never comes would live as long as its known end keeps being
// re-scanned.
func TestAParkedEdgeExpiresEvenIfItsKnownEndKeepsArriving(t *testing.T) {
	ctx := context.Background()
	clock := time.Unix(1_700_000_000, 0)
	s := New()
	s.now = func() time.Time { return clock }

	web := ontology.Node{ID: "web", Label: ontology.LabelContainer}
	toGhost := ontology.Edge{Type: ontology.EdgeConnectsTo, From: "web", To: "ghost", ExploitProbability: 0.5}
	if err := s.UpsertBatch(ctx, []ontology.Node{web}, []ontology.Edge{toGhost}); err != nil {
		t.Fatal(err)
	}
	if _, n, _ := s.PendingEdges(ctx, 10); n != 1 {
		t.Fatalf("parked %d, want 1", n)
	}

	clock = clock.Add(graph.PendingEdgeTTL - time.Hour)
	if err := s.UpsertBatch(ctx, []ontology.Node{web}, nil); err != nil { // web re-scanned
		t.Fatal(err)
	}
	if _, n, _ := s.PendingEdges(ctx, 10); n != 1 {
		t.Fatalf("parked %d just before the TTL, want 1", n)
	}

	clock = clock.Add(2 * time.Hour)
	if err := s.UpsertBatch(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, n, _ := s.PendingEdges(ctx, 10); n != 0 {
		t.Fatalf("parked %d past the TTL, want 0: re-scanning its known end kept it alive", n)
	}
	if err := s.UpsertBatch(ctx, []ontology.Node{{ID: "ghost", Label: ontology.LabelContainer}}, nil); err != nil {
		t.Fatal(err)
	}
	snap, _ := s.Snapshot(ctx)
	if len(snap.Edges) != 0 {
		t.Errorf("an expired edge still landed: %v", snap.Edges)
	}
}

// The same edge sent again while it waits restarts its wait: it was just observed.
func TestReSendingAParkedEdgeRestartsItsWait(t *testing.T) {
	ctx := context.Background()
	clock := time.Unix(1_700_000_000, 0)
	s := New()
	s.now = func() time.Time { return clock }
	e := ontology.Edge{Type: ontology.EdgeConnectsTo, From: "web", To: "ghost", ExploitProbability: 0.5}
	web := []ontology.Node{{ID: "web", Label: ontology.LabelContainer}}
	_ = s.UpsertBatch(ctx, web, []ontology.Edge{e})
	clock = clock.Add(graph.PendingEdgeTTL - time.Hour)
	_ = s.UpsertBatch(ctx, web, []ontology.Edge{e})
	clock = clock.Add(2 * time.Hour)
	_ = s.UpsertBatch(ctx, nil, nil)
	if _, n, _ := s.PendingEdges(ctx, 10); n != 1 {
		t.Fatalf("parked %d, want 1: the edge was re-observed an hour before the old TTL", n)
	}
}
