package connector

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Publisher pushes collected events onto the bus (implemented by broker.Broker).
type Publisher interface {
	Publish(ctx context.Context, ev ontology.Event) error
}

// Leader gates collection so that, with multiple replicas, exactly one process
// pulls from each external system — a connector firing from every replica would
// multiply API calls and trip the provider's rate limits. A single-process
// deploy is always the leader.
type Leader interface {
	IsLeader(ctx context.Context) bool
}

type alwaysLeader struct{}

func (alwaysLeader) IsLeader(context.Context) bool { return true }

// Status is a connector's last-run health, surfaced for ops (GET /connectors).
type Status struct {
	Source        string    `json:"source"`
	LastRunAt     time.Time `json:"lastRunAt,omitempty"`
	LastOK        bool      `json:"lastOk"`
	LastError     string    `json:"lastError,omitempty"`
	EventsLastRun int       `json:"eventsLastRun"`
	Runs          int64     `json:"runs"`
}

// Scheduler periodically asks each connector to Collect and publishes the result
// onto the bus, leader-gated. It mirrors analyzer.Service: a ticker loop with a
// run-once core, per-connector error isolation (one failing source never stops
// the others), and metrics + structured logs.
type Scheduler struct {
	pub        Publisher
	connectors []Connector
	interval   time.Duration
	timeout    time.Duration
	leader     Leader
	tenant     string

	mu     sync.Mutex
	status map[string]*Status
}

// NewScheduler builds a scheduler over the given connectors. A non-positive
// interval falls back to 15 minutes (time.NewTicker panics on ≤0).
func NewScheduler(pub Publisher, interval time.Duration, conns ...Connector) *Scheduler {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	s := &Scheduler{
		pub: pub, connectors: conns, interval: interval,
		leader: alwaysLeader{}, tenant: graph.DefaultTenant,
		status: make(map[string]*Status, len(conns)),
	}
	for _, c := range conns {
		s.status[c.Source()] = &Status{Source: c.Source()}
	}
	return s
}

// WithLeader gates collection on leadership so replicas don't duplicate pulls.
// A nil leader keeps the default (always leader). Returns the scheduler.
func (s *Scheduler) WithLeader(l Leader) *Scheduler {
	if l != nil {
		s.leader = l
	}
	return s
}

// WithTenant routes every collected event to a specific tenant's graph. Empty
// keeps the default tenant. Returns the scheduler.
func (s *Scheduler) WithTenant(t string) *Scheduler {
	if t != "" {
		s.tenant = graph.NormalizeTenant(t)
	}
	return s
}

// WithTimeout bounds a single connector's Collect, so one hung external call
// (a stalled cloud API) can't block the other connectors or the ticker. A
// non-positive value leaves Collect unbounded (the parent context still applies).
// Returns the scheduler.
func (s *Scheduler) WithTimeout(d time.Duration) *Scheduler {
	if d > 0 {
		s.timeout = d
	}
	return s
}

// Enabled reports whether any connector is registered.
func (s *Scheduler) Enabled() bool { return len(s.connectors) > 0 }

// Run blocks, collecting once immediately (so the first pull doesn't wait a full
// interval) and then on every tick, until ctx is cancelled. A no-op (returns
// nil) when no connector is registered.
func (s *Scheduler) Run(ctx context.Context) error {
	if !s.Enabled() {
		return nil
	}
	slog.Info("connector scheduler started", "connectors", s.sources(), "interval", s.interval, "tenant", s.tenant)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	s.collectAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			s.collectAll(ctx)
		}
	}
}

// collectAll runs every connector once, leader-gated.
func (s *Scheduler) collectAll(ctx context.Context) {
	if !s.leader.IsLeader(ctx) {
		return
	}
	for _, c := range s.connectors {
		s.collectOne(ctx, c)
	}
}

// collectOne pulls and publishes one connector's events, isolating its failures
// from the others. A connector may return both events and an error (a partial
// pull where one sub-feed failed): we publish what we got and still record the
// run as degraded, so a transient IAM hiccup doesn't discard the network feed.
func (s *Scheduler) collectOne(ctx context.Context, c Connector) {
	src := c.Source()
	cctx := ctx
	if s.timeout > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	events, cerr := c.Collect(cctx)
	now := time.Now()

	var published, nodes int
	for _, ev := range events {
		ev.Tenant = s.tenant // route to the configured tenant's graph
		if perr := s.pub.Publish(ctx, ev); perr != nil {
			if errors.Is(perr, context.Canceled) {
				return
			}
			metrics.ConnectorRuns.WithLabelValues(src, "error").Inc()
			s.record(src, now, false, "publish: "+perr.Error(), published)
			slog.Error("connector publish failed", "source", src, "err", perr)
			return
		}
		published++
		nodes += len(ev.Nodes)
		metrics.ConnectorEvents.WithLabelValues(src).Inc()
	}

	if cerr != nil {
		metrics.ConnectorRuns.WithLabelValues(src, "error").Inc()
		s.record(src, now, false, cerr.Error(), published)
		slog.Warn("connector collect degraded (published partial)", "source", src, "events", published, "err", cerr)
		return
	}
	metrics.ConnectorRuns.WithLabelValues(src, "ok").Inc()
	s.record(src, now, true, "", published)
	slog.Info("connector collected", "source", src, "events", published, "nodes", nodes)
}

func (s *Scheduler) record(src string, at time.Time, ok bool, errMsg string, events int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status[src]
	if st == nil {
		st = &Status{Source: src}
		s.status[src] = st
	}
	st.LastRunAt = at
	st.LastOK = ok
	st.LastError = errMsg
	st.EventsLastRun = events
	st.Runs++
}

// Status returns a snapshot of every connector's health, source-sorted, for the
// GET /connectors ops endpoint.
func (s *Scheduler) Status() []Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Status, 0, len(s.status))
	for _, st := range s.status {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}

func (s *Scheduler) sources() []string {
	out := make([]string, 0, len(s.connectors))
	for _, c := range s.connectors {
		out = append(out, c.Source())
	}
	return out
}
