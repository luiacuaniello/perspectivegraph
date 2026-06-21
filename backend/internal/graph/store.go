// Package graph defines the Store abstraction over the graph core and the
// data structures the rest of the system reasons about. Two implementations
// exist: an in-memory store (dev/tests) and an Apache AGE store (production).
package graph

import (
	"context"

	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

// Snapshot is an in-memory view of the whole graph, used by the analyzer to run
// traversal without round-tripping the database per edge.
type Snapshot struct {
	Nodes []ontology.Node
	Edges []ontology.Edge
}

// NodeByID indexes the snapshot's nodes for O(1) lookup.
func (s Snapshot) NodeByID() map[string]ontology.Node {
	m := make(map[string]ontology.Node, len(s.Nodes))
	for _, n := range s.Nodes {
		m[n.ID] = n
	}
	return m
}

// Store is the persistence contract for the graph core. Writes are idempotent
// upserts keyed by node/edge identity so re-ingesting the same scan is safe.
type Store interface {
	// UpsertNode creates or updates a vertex by its ID.
	UpsertNode(ctx context.Context, n ontology.Node) error
	// UpsertEdge creates or updates a directed relationship between two nodes.
	UpsertEdge(ctx context.Context, e ontology.Edge) error
	// Snapshot returns the full graph for traversal/visualization.
	Snapshot(ctx context.Context) (Snapshot, error)
	// Ping verifies the backend is reachable.
	Ping(ctx context.Context) error
	// Close releases resources.
	Close() error
}

// ApplyEvent upserts every node and edge carried by an event. Nodes are written
// before edges so edge endpoints always exist.
func ApplyEvent(ctx context.Context, s Store, ev ontology.Event) error {
	for _, n := range ev.Nodes {
		if err := s.UpsertNode(ctx, n); err != nil {
			return err
		}
	}
	for _, e := range ev.Edges {
		if err := s.UpsertEdge(ctx, e); err != nil {
			return err
		}
	}
	return nil
}
