// Package memory is an in-memory graph.Store. It lets the whole backend run
// (and be unit-tested) without a database, and serves as the reference
// implementation for the Store contract.
package memory

import (
	"context"
	"sync"

	"github.com/aegisgraph/aegisgraph/internal/graph"
	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

type edgeKey struct {
	typ      ontology.EdgeType
	from, to string
}

// Store is a thread-safe in-memory graph.
type Store struct {
	mu    sync.RWMutex
	nodes map[string]ontology.Node
	edges map[edgeKey]ontology.Edge
}

// New returns an empty in-memory store.
func New() *Store {
	return &Store{
		nodes: make(map[string]ontology.Node),
		edges: make(map[edgeKey]ontology.Edge),
	}
}

func (s *Store) UpsertNode(_ context.Context, n ontology.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.nodes[n.ID]; ok {
		// Merge properties so observations from different collectors accumulate.
		merged := mergeProps(existing.Properties, n.Properties)
		n.Properties = merged
		if n.Name == "" {
			n.Name = existing.Name
		}
	}
	s.nodes[n.ID] = n
	return nil
}

func (s *Store) UpsertEdge(_ context.Context, e ontology.Edge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.edges[edgeKey{e.Type, e.From, e.To}] = e
	return nil
}

func (s *Store) Snapshot(_ context.Context) (graph.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := graph.Snapshot{
		Nodes: make([]ontology.Node, 0, len(s.nodes)),
		Edges: make([]ontology.Edge, 0, len(s.edges)),
	}
	for _, n := range s.nodes {
		snap.Nodes = append(snap.Nodes, n)
	}
	for _, e := range s.edges {
		snap.Edges = append(snap.Edges, e)
	}
	return snap, nil
}

func (s *Store) Ping(context.Context) error { return nil }
func (s *Store) Close() error               { return nil }

func mergeProps(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
