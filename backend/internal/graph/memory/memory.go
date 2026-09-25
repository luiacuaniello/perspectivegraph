// Package memory is an in-memory graph.Store. It lets the whole backend run
// (and be unit-tested) without a database, and serves as the reference
// implementation for the Store contract.
package memory

import (
	"context"
	"fmt"
	"sort"
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

	// Edges parked by UpsertBatch until their missing endpoint arrives (see
	// graph.EdgeParker), and an index from each endpoint id to the edges naming it.
	pending      map[edgeKey]parked
	pendingByID  map[string]map[edgeKey]struct{}
	pendingSwept time.Time
	now          func() time.Time
}

type parked struct {
	edge ontology.Edge
	at   time.Time
}

// New returns an empty in-memory store.
func New() *Store {
	return &Store{
		nodes:       make(map[string]ontology.Node),
		edges:       make(map[edgeKey]ontology.Edge),
		pending:     make(map[edgeKey]parked),
		pendingByID: make(map[string]map[edgeKey]struct{}),
		now:         time.Now,
	}
}

func (s *Store) UpsertNode(_ context.Context, n ontology.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upsertNodeLocked(n)
	return nil
}

func (s *Store) upsertNodeLocked(n ontology.Node) {
	if existing, ok := s.nodes[n.ID]; ok {
		// Merge properties so observations from different collectors accumulate.
		n.Properties = graph.MergeProps(existing.Properties, n.Properties)
		if n.Name == "" {
			n.Name = existing.Name
		}
	}
	s.nodes[n.ID] = n
}

// UpsertBatch writes nodes, then every edge that can land, and parks the rest until
// their endpoint arrives (graph.EdgeParker). Edges already parked for one of these nodes
// are tried again first, so this event's own copy of an edge, being newer, wins.
func (s *Store) UpsertBatch(_ context.Context, nodes []ontology.Node, edges []ontology.Edge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepPendingLocked(now)
	for _, n := range nodes {
		s.upsertNodeLocked(n)
	}
	for _, p := range s.takePendingLocked(nodes) {
		if !s.landLocked(p.edge) {
			s.parkLocked(p.edge, p.at) // still waiting for its other end: keep its age
		}
	}
	for _, e := range edges {
		if !s.landLocked(e) {
			s.parkLocked(e, now)
		}
	}
	return nil
}

// PendingEdges implements graph.EdgeParker.
func (s *Store) PendingEdges(_ context.Context, limit int) ([]ontology.Edge, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := make([]parked, 0, len(s.pending))
	for _, p := range s.pending {
		all = append(all, p)
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].at.Equal(all[j].at) {
			return all[i].at.Before(all[j].at)
		}
		a, b := all[i].edge, all[j].edge
		return a.From+"\x00"+a.To+"\x00"+string(a.Type) < b.From+"\x00"+b.To+"\x00"+string(b.Type)
	})
	if limit >= 0 && len(all) > limit {
		all = all[:limit]
	}
	out := make([]ontology.Edge, len(all))
	for i, p := range all {
		out[i] = p.edge
	}
	return out, len(s.pending), nil
}

func (s *Store) landLocked(e ontology.Edge) bool {
	_, fromOK := s.nodes[e.From]
	_, toOK := s.nodes[e.To]
	if !fromOK || !toOK {
		return false
	}
	s.edges[edgeKey{e.Type, e.From, e.To}] = e
	return true
}

func (s *Store) parkLocked(e ontology.Edge, at time.Time) {
	k := edgeKey{e.Type, e.From, e.To}
	s.pending[k] = parked{edge: e, at: at}
	for _, id := range []string{e.From, e.To} {
		if s.pendingByID[id] == nil {
			s.pendingByID[id] = map[edgeKey]struct{}{}
		}
		s.pendingByID[id][k] = struct{}{}
	}
}

func (s *Store) unparkLocked(k edgeKey) {
	delete(s.pending, k)
	for _, id := range []string{k.from, k.to} {
		delete(s.pendingByID[id], k)
		if len(s.pendingByID[id]) == 0 {
			delete(s.pendingByID, id)
		}
	}
}

// takePendingLocked removes and returns the parked edges naming any of these nodes.
func (s *Store) takePendingLocked(nodes []ontology.Node) []parked {
	var out []parked
	for _, n := range nodes {
		for k := range s.pendingByID[n.ID] {
			if p, ok := s.pending[k]; ok {
				out = append(out, p)
				s.unparkLocked(k)
			}
		}
	}
	return out
}

// sweepPendingLocked drops edges parked longer than graph.PendingEdgeTTL. It walks every
// parked edge, so it runs at most once a minute rather than on every write.
func (s *Store) sweepPendingLocked(now time.Time) {
	if now.Sub(s.pendingSwept) < time.Minute {
		return
	}
	s.pendingSwept = now
	for k, p := range s.pending {
		if now.Sub(p.at) > graph.PendingEdgeTTL {
			s.unparkLocked(k)
		}
	}
}

// UpsertEdge rejects edges whose endpoints are not in the graph yet - same
// contract as the AGE store: the broker redelivers the event with backoff, so
// the edge lands once its nodes arrive instead of dangling.
func (s *Store) UpsertEdge(_ context.Context, e ontology.Edge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, fromOK := s.nodes[e.From]
	_, toOK := s.nodes[e.To]
	if !fromOK || !toOK {
		return fmt.Errorf("upsert edge %s %s->%s: %w", e.Type, e.From, e.To, graph.ErrEndpointsMissing)
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

// SnapshotSince returns the nodes and edges observed at or after `since` (unix
// seconds) - the incremental delta the analyzer patches onto its cached snapshot
// instead of re-reading the whole graph. Elements without a last_seen stamp are
// omitted: they predate staleness tracking and are already in the consumer's
// initial full snapshot, so a delta never needs to re-ship them.
func (s *Store) SnapshotSince(_ context.Context, since int64) (graph.Delta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var d graph.Delta
	for _, n := range s.nodes {
		if ls, ok := graph.LastSeen(n.Properties); ok && ls >= since {
			d.Nodes = append(d.Nodes, n)
		}
	}
	for _, e := range s.edges {
		if ls, ok := graph.LastSeen(e.Properties); ok && ls >= since {
			d.Edges = append(d.Edges, e)
		}
	}
	return d, nil
}

// Prune removes nodes and edges last observed before the cutoff (and any edge
// left dangling by a removed node). Elements with no last_seen stamp are kept -
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
