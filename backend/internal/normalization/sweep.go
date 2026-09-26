package normalization

import (
	"context"
	"log/slog"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
)

// Sweep applies the omissions of a complete snapshot, once every message of the ingest
// that carried it has reached the graph: whatever source asserted in scope before taken
// and did not assert again is retracted, and an element nobody asserts any more leaves
// the graph (graph.Sweeper). The broker calls it; it is the only way the engine forgets
// an asset before staleness pruning would.
func (n *Normalizer) Sweep(ctx context.Context, tenant, source, scope string, taken time.Time) error {
	store, err := n.manager.For(ctx, tenant)
	if err != nil {
		return err
	}
	scope = CanonicalScope(scope) // as Handle recorded it
	stats, err := store.Sweep(ctx, source, scope, taken)
	if err != nil {
		metrics.GraphSweeps.WithLabelValues(source, "error").Inc()
		return err
	}
	metrics.GraphSweeps.WithLabelValues(source, "ok").Inc()
	metrics.GraphSwept.WithLabelValues("node").Add(float64(stats.Nodes))
	metrics.GraphSwept.WithLabelValues("edge").Add(float64(stats.Edges))
	metrics.GraphSwept.WithLabelValues("parked").Add(float64(stats.Parked))
	if stats.Removed() {
		slog.Info("complete snapshot applied: retracted what the source no longer lists",
			"tenant", tenant, "source", source, "scope", scope,
			"nodes", stats.Nodes, "edges", stats.Edges, "parked", stats.Parked)
	}
	return nil
}
