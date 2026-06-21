package analyzer

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/aegisgraph/aegisgraph/internal/graph"
	"github.com/aegisgraph/aegisgraph/internal/policy"
)

// Sink receives the critical paths found on each analysis pass (e.g. the action
// layer that posts PR comments). It is optional.
type Sink interface {
	OnCriticalPaths(ctx context.Context, paths []AttackPath)
}

// Service re-computes attack paths on an interval and caches the latest result
// so the API can serve it without recomputing per request.
type Service struct {
	store    graph.Store
	interval time.Duration
	sink     Sink
	policy   *policy.Engine

	mu         sync.RWMutex
	latest     []AttackPath
	violations []policy.Violation
}

func NewService(store graph.Store, interval time.Duration, sink Sink) *Service {
	return &Service{store: store, interval: interval, sink: sink}
}

// WithPolicy attaches an invariant engine; its violations are recomputed on
// every analysis pass. Returns the service for chaining.
func (s *Service) WithPolicy(e *policy.Engine) *Service {
	s.policy = e
	return s
}

// Latest returns the most recently computed attack paths.
func (s *Service) Latest() []AttackPath {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AttackPath, len(s.latest))
	copy(out, s.latest)
	return out
}

// Violations returns the invariant violations from the latest pass.
func (s *Service) Violations() []policy.Violation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]policy.Violation, len(s.violations))
	copy(out, s.violations)
	return out
}

// Run computes immediately, then on every tick, until ctx is cancelled.
func (s *Service) Run(ctx context.Context) error {
	s.runOnce(ctx)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			s.runOnce(ctx)
		}
	}
}

func (s *Service) runOnce(ctx context.Context) {
	snap, err := s.store.Snapshot(ctx)
	if err != nil {
		slog.Error("analyzer: snapshot failed", "err", err)
		return
	}
	paths := FindCriticalPaths(snap)

	var violations []policy.Violation
	if s.policy != nil {
		violations = s.policy.Evaluate(snap)
	}

	s.mu.Lock()
	s.latest = paths
	s.violations = violations
	s.mu.Unlock()

	slog.Info("analyzer pass complete",
		"nodes", len(snap.Nodes), "edges", len(snap.Edges),
		"critical_paths", len(paths), "policy_violations", len(violations))

	for _, v := range violations {
		slog.Warn("policy invariant violated", "id", v.InvariantID, "severity", v.Severity)
	}

	if s.sink != nil && len(paths) > 0 {
		s.sink.OnCriticalPaths(ctx, paths)
	}
}
