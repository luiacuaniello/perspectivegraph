// Package memory is an in-memory graph.Store. It lets the whole backend run
// (and be unit-tested) without a database, and serves as the reference
// implementation for the Store contract.
package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
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
		n.Properties = graph.MergeProps(existing.Properties, n.Properties)
		if n.Name == "" {
			n.Name = existing.Name
		}
	}
	s.nodes[n.ID] = n
	return nil
}

// UpsertEdge rejects edges whose endpoints are not in the graph yet — same
// contract as the AGE store: the broker redelivers the event with backoff, so
// the edge lands once its nodes arrive instead of dangling.
func (s *Store) UpsertEdge(_ context.Context, e ontology.Edge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, fromOK := s.nodes[e.From]
	_, toOK := s.nodes[e.To]
	if !fromOK || !toOK {
		return fmt.Errorf("upsert edge %s %s->%s: endpoint node(s) not in graph yet", e.Type, e.From, e.To)
	}
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

// Prune removes nodes and edges last observed before the cutoff (and any edge
// left dangling by a removed node). Elements with no last_seen stamp are kept —
// they predate staleness tracking and must not vanish silently.
func (s *Store) Prune(_ context.Context, before time.Time) (graph.PruneStats, error) {
	cutoff := before.Unix()
	s.mu.Lock()
	defer s.mu.Unlock()

	var stats graph.PruneStats
	removed := make(map[string]bool)
	for id, n := range s.nodes {
		if ls, ok := graph.LastSeen(n.Properties); ok && ls < cutoff {
			delete(s.nodes, id)
			removed[id] = true
			stats.Nodes++
		}
	}
	for k, e := range s.edges {
		ls, ok := graph.LastSeen(e.Properties)
		stale := ok && ls < cutoff
		if stale || removed[e.From] || removed[e.To] {
			delete(s.edges, k)
			stats.Edges++
		}
	}
	return stats, nil
}

func (s *Store) Ping(context.Context) error { return nil }
func (s *Store) Close() error               { return nil }
