// Package graph defines the Store abstraction over the graph core and the
// data structures the rest of the system reasons about. Two implementations
// exist: an in-memory store (dev/tests) and an Apache AGE store (production).
package graph

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
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

// RawPath is one ordered route through the graph: nodes[0]→…→nodes[n], with
// edges[i] joining nodes[i] and nodes[i+1]. It is the neutral shape a PathStore
// returns so the analyzer can score it into an attack path without the store
// depending on the analyzer package.
type RawPath struct {
	Nodes []ontology.Node
	Edges []ontology.Edge
}

// PruneStats reports how many graph elements a Prune call removed.
type PruneStats struct {
	Nodes int
	Edges int
}

// Pruner is an OPTIONAL Store capability: delete nodes and edges whose last
// observation predates a cutoff, so assets that have fallen out of the source
// feeds stop generating phantom attack paths. Elements without a last_seen stamp
// are never pruned (grandfathered). Stores that don't implement it simply never
// prune. Pruning a node also removes its incident edges.
type Pruner interface {
	Prune(ctx context.Context, before time.Time) (PruneStats, error)
}

// LastSeen reads the unix-seconds last-observation stamp from a property bag,
// tolerating the numeric types the two stores return (memory keeps the int64 it
// was written with; AGE agtype round-trips numbers as float64). Reports false
// when the stamp is absent - the caller treats that as "never prune".
func LastSeen(props map[string]any) (int64, bool) {
	if props == nil {
		return 0, false
	}
	switch v := props[ontology.PropLastSeen].(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case float64:
		return int64(v), true
	}
	return 0, false
}

// Delta is the set of graph elements observed at or after a watermark: idempotent
// upserts a consumer can patch onto a cached snapshot. It carries no deletions -
// the only source of removals is the TTL pruner, and the analyzer rebuilds a full
// snapshot whenever it prunes (and periodically), so a delta only ever adds or
// updates. Both stores stamp last_seen on every write (see ApplyEvent), which is
// what makes the "since" filter possible.
type Delta struct {
	Nodes []ontology.Node
	Edges []ontology.Edge
}

// DeltaStore is an OPTIONAL Store capability: return just the elements observed at
// or after `since` (unix seconds), so a consumer holding a cached snapshot can
// patch it instead of re-reading the whole graph each pass - the scale win on a
// large, slowly-changing graph (it avoids the full DB round-trip + deserialization
// every analyzer pass). Stores that don't implement it fall back to full Snapshot.
type DeltaStore interface {
	SnapshotSince(ctx context.Context, since int64) (Delta, error)
}

// PathStore is an OPTIONAL Store capability: compute internet-exposed →
// crown-jewel routes inside the database (e.g. AGE's Cypher variable-length
// match over native node properties) instead of pulling the whole graph and
// running a client-side traversal. Stores that don't implement it fall back to
// Snapshot + the in-process traversal. `maxHops` bounds path length.
type PathStore interface {
	CriticalPaths(ctx context.Context, maxHops int) ([]RawPath, error)
}

// ErrEndpointsMissing is wrapped by a write that could not place an edge because one
// of its endpoints is not in the graph yet. It is worth a redelivery - the node it
// waits for may be in an event still on its way - and it never stops the rest of the
// event: every node and every other edge is written first.
var ErrEndpointsMissing = errors.New("edge endpoint(s) not in the graph yet")

// BatchWriter is an OPTIONAL Store capability: write an event's nodes, then its edges,
// as one unit. A store with a per-write cost - a transaction, a round trip - pays it
// once per event instead of once per element. An edge whose endpoint is missing is
// skipped, everything else is written, and the call then returns an error wrapping
// ErrEndpointsMissing.
type BatchWriter interface {
	UpsertBatch(ctx context.Context, nodes []ontology.Node, edges []ontology.Edge) error
}

// Store is the persistence contract for the graph core. Writes are idempotent
// upserts keyed by node/edge identity so re-ingesting the same scan is safe.
type Store interface {
	// UpsertNode creates or updates a vertex by its ID, merging properties
	// with previous observations (see MergeProps).
	UpsertNode(ctx context.Context, n ontology.Node) error
	// UpsertEdge creates or updates a directed relationship between two nodes.
	// It returns an error wrapping ErrEndpointsMissing when either endpoint is not
	// in the graph yet: the broker redelivers the event with backoff, so the edge
	// lands once its nodes arrive (eventual consistency instead of dangling edges).
	UpsertEdge(ctx context.Context, e ontology.Edge) error
	// Snapshot returns the full graph for traversal/visualization.
	Snapshot(ctx context.Context) (Snapshot, error)
	// Ping verifies the backend is reachable.
	Ping(ctx context.Context) error
	// Close releases resources.
	Close() error
}

// MergeProps overlays b onto a without mutating either map. It is the Store
// contract's property-merge rule: upserting a node accumulates properties from
// successive observations (later writes win per key), so a stub re-upsert can
// never erase what another collector recorded. Every implementation must apply
// it in UpsertNode.
func MergeProps(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// VersionedStore wraps a Store with a monotonically increasing write version,
// letting consumers (the analyzer) skip work when nothing changed since their
// last read. It counts successful writes made through this process; writers
// outside the process are invisible to it - acceptable while normalization is
// the single writer.
type VersionedStore struct {
	Store
	version atomic.Int64
}

func NewVersionedStore(s Store) *VersionedStore { return &VersionedStore{Store: s} }

func (v *VersionedStore) UpsertNode(ctx context.Context, n ontology.Node) error {
	err := v.Store.UpsertNode(ctx, n)
	if err == nil {
		v.version.Add(1)
	}
	return err
}

func (v *VersionedStore) UpsertEdge(ctx context.Context, e ontology.Edge) error {
	err := v.Store.UpsertEdge(ctx, e)
	if err == nil {
		v.version.Add(1)
	}
	return err
}

// UpsertBatch writes through the wrapped store's BatchWriter when it has one, and
// element by element otherwise. The version moves whenever something was written -
// including a batch that landed everything but an edge still waiting for its endpoint.
func (v *VersionedStore) UpsertBatch(ctx context.Context, nodes []ontology.Node, edges []ontology.Edge) error {
	bw, ok := v.Store.(BatchWriter)
	if !ok {
		return upsertEach(ctx, v, nodes, edges) // through v, so each write counts
	}
	err := bw.UpsertBatch(ctx, nodes, edges)
	if (err == nil || errors.Is(err, ErrEndpointsMissing)) && len(nodes)+len(edges) > 0 {
		v.version.Add(1)
	}
	return err
}

// Version returns the current write counter.
func (v *VersionedStore) Version() int64 { return v.version.Load() }

// Prune delegates to the wrapped store's Pruner (when it has one) and bumps the
// write version when anything was removed, so the analyzer's change-detection
// recomputes and the dashboard refetches - a deletion is a graph change just like
// a write, even though it doesn't flow through UpsertNode/UpsertEdge.
func (v *VersionedStore) Prune(ctx context.Context, before time.Time) (PruneStats, error) {
	p, ok := v.Store.(Pruner)
	if !ok {
		return PruneStats{}, nil
	}
	stats, err := p.Prune(ctx, before)
	if err == nil && stats.Nodes+stats.Edges > 0 {
		v.version.Add(1)
	}
	return stats, err
}

// AsPathStore reports whether s (unwrapping a VersionedStore) can compute paths
// in the database, returning the PathStore if so. Optional capabilities aren't
// promoted through the VersionedStore wrapper, so callers go through this.
func AsPathStore(s Store) (PathStore, bool) {
	for {
		if pf, ok := s.(PathStore); ok {
			return pf, true
		}
		vs, ok := s.(*VersionedStore)
		if !ok {
			return nil, false
		}
		s = vs.Store
	}
}

// AsDeltaStore reports whether s (unwrapping a VersionedStore) can return
// incremental deltas, returning the DeltaStore if so. Like the other optional
// capabilities it isn't promoted through the wrapper, so callers go through this.
func AsDeltaStore(s Store) (DeltaStore, bool) {
	for {
		if ds, ok := s.(DeltaStore); ok {
			return ds, true
		}
		vs, ok := s.(*VersionedStore)
		if !ok {
			return nil, false
		}
		s = vs.Store
	}
}

// AsPruner reports whether s can prune stale elements. A *VersionedStore is
// preferred (its Prune bumps the write version), so callers pass the versioned
// store they already hold and get version-aware pruning for free.
func AsPruner(s Store) (Pruner, bool) {
	for {
		if p, ok := s.(Pruner); ok {
			return p, true
		}
		vs, ok := s.(*VersionedStore)
		if !ok {
			return nil, false
		}
		s = vs.Store
	}
}

// ApplyEvent upserts every node and edge carried by an event. Nodes are written
// before edges so edge endpoints always exist. Each element is stamped with the
// event's observation time (last_seen) so the staleness pruner can later tell a
// still-present asset from one that fell out of the feeds.
//
// A store that is a BatchWriter gets the whole event in one call. An edge whose
// endpoint is not in the graph yet no longer stops the event where it stands: the
// nodes and the other edges are written, and the error returned afterwards (wrapping
// ErrEndpointsMissing) earns the event a redelivery for the edges that are left. It
// used to return at the first such edge, so every edge listed after it waited on a
// node it had nothing to do with - and was lost with it if that node never came.
func ApplyEvent(ctx context.Context, s Store, ev ontology.Event) error {
	seen := ev.ObservedAt
	if seen.IsZero() {
		seen = time.Now()
	}
	ts := seen.Unix()

	// The ontology is a closed set and this is the single writer, so this is where the
	// contract holds for every backend. It was previously checked only by the Apache
	// AGE store, which left the in-memory default - what the demo runs - accepting any
	// string as a label or an edge type, while downstream code (the AI prompt renderer,
	// the Cypher builder) assumes the closed set.
	//
	// A value outside the vocabulary is DROPPED, not returned as an error: an error
	// Naks the event and the broker redelivers it, so one malformed node would loop
	// forever. The endpoint-missing error below stays an error precisely because that
	// one IS worth redelivering - the node it waits for is still arriving.
	dropped := map[string]bool{}
	nodes := make([]ontology.Node, 0, len(ev.Nodes))
	for _, n := range ev.Nodes {
		if !ontology.IsValidLabel(n.Label) {
			slog.Warn("dropping node outside the ontology",
				"id", n.ID, "label", ontology.Truncate(string(n.Label)), "source", ev.Source)
			dropped[n.ID] = true
			continue
		}
		n.Properties = withLastSeen(n.Properties, ts)
		nodes = append(nodes, n)
	}
	edges := make([]ontology.Edge, 0, len(ev.Edges))
	for _, e := range ev.Edges {
		// An edge to a node this event dropped can never land, so it is dropped with it
		// rather than left to fail the endpoint check and be redelivered forever.
		if !ontology.IsValidEdgeType(e.Type) || dropped[e.From] || dropped[e.To] {
			slog.Warn("dropping edge outside the ontology",
				"type", ontology.Truncate(string(e.Type)), "from", e.From, "to", e.To, "source", ev.Source)
			continue
		}
		e.Properties = withLastSeen(e.Properties, ts)
		edges = append(edges, e)
	}
	if bw, ok := s.(BatchWriter); ok {
		return bw.UpsertBatch(ctx, nodes, edges)
	}
	return upsertEach(ctx, s, nodes, edges)
}

// upsertEach is the element-by-element write for a store that is not a BatchWriter,
// with the same contract: nodes, then every edge that can land, then an error wrapping
// ErrEndpointsMissing for the ones that could not.
func upsertEach(ctx context.Context, s Store, nodes []ontology.Node, edges []ontology.Edge) error {
	for _, n := range nodes {
		if err := s.UpsertNode(ctx, n); err != nil {
			return err
		}
	}
	var waiting []ontology.Edge
	for _, e := range edges {
		if err := s.UpsertEdge(ctx, e); err != nil {
			if errors.Is(err, ErrEndpointsMissing) {
				waiting = append(waiting, e)
				continue
			}
			return err
		}
	}
	return EndpointsMissing(waiting)
}

// EndpointsMissing reports the edges a write had to leave out, or nil if there were
// none. The first one is named, so the log line says what the event is waiting for.
func EndpointsMissing(waiting []ontology.Edge) error {
	if len(waiting) == 0 {
		return nil
	}
	e := waiting[0]
	return fmt.Errorf("%d edge(s) left for a redelivery, e.g. %s %s->%s: %w",
		len(waiting), e.Type, e.From, e.To, ErrEndpointsMissing)
}

// withLastSeen returns a copy of props with the last_seen stamp set, without
// mutating the caller's map (the event may be retained/redelivered).
func withLastSeen(props map[string]any, ts int64) map[string]any {
	out := make(map[string]any, len(props)+1)
	for k, v := range props {
		out[k] = v
	}
	out[ontology.PropLastSeen] = ts
	return out
}
