package analyzer

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/internal/notify"
	"github.com/luiacuaniello/perspectivegraph/internal/policy"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// Sink receives the critical paths found on each analysis pass (e.g. the action
// layer that posts PR comments). It is optional.
type Sink interface {
	OnCriticalPaths(ctx context.Context, paths []AttackPath)
}

// riskSeed fixes the Monte Carlo seed for the cached, per-pass risk simulation
// so the dashboard sees stable numbers between polls (and we don't recompute it
// on every request - only once per analyzer pass).
const riskSeed = 1

// DefaultMaxHops bounds the length of attack paths the DB-side finder enumerates.
// Real attack chains are short; this also keeps AGE's variable-length match cheap.
const DefaultMaxHops = 12

// forceRescanEvery bounds how long a replica can rely on its per-process write
// counter before recomputing anyway. The version counter only sees writes made
// *through this process*, so in a multi-replica deployment a replica that didn't
// ingest the change would otherwise serve a stale cache; forcing a periodic
// rescan re-reads the shared graph. At a 30s interval, 10 ⇒ ≤5 min staleness.
const forceRescanEvery = 10

// Leader reports whether this process should perform at-most-once external
// actions (drift webhooks, PR comments). In a single-replica deploy it is always
// true; with replicas, a leader election makes exactly one process the actor.
type Leader interface {
	IsLeader(ctx context.Context) bool
}

type alwaysLeader struct{}

func (alwaysLeader) IsLeader(context.Context) bool { return true }

// tenantState caches one tenant's latest analysis.
type tenantState struct {
	latest      []AttackPath
	risk        RiskSimulation
	violations  []policy.Violation
	lastVersion int64
	skips       int // consecutive version-unchanged ticks skipped
	analyzedAt  time.Time
	passes      int64
	hasRun      bool

	// Staleness pruning bookkeeping.
	lastPrune    time.Time // when the pruner last ran for this tenant
	lastPrunedAt time.Time // when it last actually removed something
	prunedNodes  int       // lifetime stale nodes removed
	prunedEdges  int       // lifetime stale edges removed

	// Incremental-snapshot cache (only used when WithIncremental is on and the
	// store supports deltas). The analyzer goroutine is the single writer, like
	// the other non-locked fields above.
	cacheNodes      map[string]ontology.Node // resident graph, patched by deltas
	cacheEdges      map[edgeID]ontology.Edge
	cacheValid      bool  // a full snapshot has seeded the cache
	snapWatermark   int64 // unix seconds; next delta fetches last_seen >= this
	passesSinceFull int   // forces a periodic full re-read (drift safety net)
}

// edgeID keys an edge in the incremental cache by its identity (type + endpoints),
// matching the stores' upsert key so a delta overwrites the right entry.
type edgeID struct {
	typ      ontology.EdgeType
	from, to string
}

// Service re-computes attack paths per tenant on an interval and caches the
// latest result so the API can serve it without recomputing per request.
type Service struct {
	manager  *graph.Manager
	interval time.Duration
	sink     Sink
	policy   *policy.Engine
	notifier notify.Notifier
	leader   Leader
	maxHops  int
	dbPaths  bool // compute critical paths in the DB (opt-in) instead of in-process Dijkstra

	workers     int  // per-seed pathfinding parallelism (0 = auto = GOMAXPROCS)
	incremental bool // patch a cached snapshot from deltas instead of re-reading the whole graph each pass

	ttl        time.Duration // staleness TTL; 0 disables pruning
	pruneEvery time.Duration // how often to run the (leader-only) pruner

	history *history.Store // temporal store (path lifecycle + posture trend)

	mu     sync.RWMutex
	states map[string]*tenantState
}

// versioner is implemented by graph.VersionedStore.
type versioner interface{ Version() int64 }

func NewService(manager *graph.Manager, interval time.Duration, sink Sink) *Service {
	if interval <= 0 {
		// time.NewTicker panics on non-positive intervals; config validates
		// too, but guard here so no caller can crash the analyzer loop.
		interval = 30 * time.Second
	}
	return &Service{manager: manager, interval: interval, sink: sink,
		notifier: notify.Noop{}, leader: alwaysLeader{}, maxHops: DefaultMaxHops,
		states: map[string]*tenantState{}}
}

// WithMaxHops bounds the length of attack paths found. A non-positive value
// keeps the default. Returns the service for chaining.
func (s *Service) WithMaxHops(h int) *Service {
	if h > 0 {
		s.maxHops = h
	}
	return s
}

// WithTTL enables staleness pruning: nodes/edges not observed within d are
// removed (leader-only) so assets that left the source feeds stop producing
// phantom attack paths. A non-positive d disables pruning (the default). The
// pruner runs at most once per derived cadence (≈ d/6, clamped to [interval, 1h])
// so it isn't re-scanning every pass. Returns the service for chaining.
func (s *Service) WithTTL(d time.Duration) *Service {
	if d <= 0 {
		s.ttl = 0
		return s
	}
	s.ttl = d
	every := d / 6
	if every < s.interval {
		every = s.interval
	}
	if every > time.Hour {
		every = time.Hour
	}
	s.pruneEvery = every
	return s
}

// WithHistory attaches the temporal store; each pass records the open paths'
// lifecycle (for age/MTTR/reopens) and a posture sample (for the trend). A nil
// store is a no-op. Returns the service for chaining.
func (s *Service) WithHistory(h *history.Store) *Service {
	s.history = h
	return s
}

// WithDBPaths opts into computing critical paths in the database (AGE Cypher)
// instead of the default in-process Dijkstra. Off by default: the variable-length
// enumeration is unbounded in the worst case, so it's reserved for graphs an
// operator knows are bounded. Returns the service for chaining.
func (s *Service) WithDBPaths(on bool) *Service {
	s.dbPaths = on
	return s
}

// WithWorkers sets how many goroutines fan out the per-seed shortest-path searches
// each pass. n <= 0 keeps the automatic default (GOMAXPROCS). The per-seed Dijkstra
// runs are independent reads over an immutable adjacency, so this scales the
// dominant per-pass cost on a large graph with many entry points without changing
// the result. Returns the service for chaining.
func (s *Service) WithWorkers(n int) *Service {
	s.workers = n
	SetPathWorkers(n)
	return s
}

// WithIncremental opts into incremental snapshotting: instead of re-reading the
// whole graph every pass, the analyzer keeps a resident snapshot and patches it
// with just the elements observed since the last pass (a store delta). It still
// recomputes all paths - attack paths can change non-locally - but avoids the full
// fetch + deserialization, the dominant cost on a large AGE graph. A full re-read
// still happens on the first pass, whenever the pruner removed something (deltas
// carry no deletions), periodically as a drift safety net, and if a delta fetch
// errors. Off by default (it keeps the graph resident, trading memory for fetch
// cost) and a no-op for stores without delta support. Returns the service for
// chaining.
func (s *Service) WithIncremental(on bool) *Service {
	s.incremental = on
	return s
}

// WithLeader gates external side-effects (drift alerts, PR comments) on
// leadership, so multiple replicas don't duplicate them. Returns the service for
// chaining; a nil leader keeps the default (always leader).
func (s *Service) WithLeader(l Leader) *Service {
	if l != nil {
		s.leader = l
	}
	return s
}

// WithPolicy attaches an invariant engine; its violations are recomputed on
// every analysis pass. Returns the service for chaining.
func (s *Service) WithPolicy(e *policy.Engine) *Service {
	s.policy = e
	return s
}

// WithNotifier attaches a drift-alert notifier (e.g. a Slack webhook). Returns
// the service for chaining.
func (s *Service) WithNotifier(n notify.Notifier) *Service {
	if n != nil {
		s.notifier = n
	}
	return s
}

// Latest returns the most recently computed attack paths for a tenant.
func (s *Service) Latest(tenant string) []AttackPath {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.states[graph.NormalizeTenant(tenant)]
	if st == nil {
		return nil
	}
	out := make([]AttackPath, len(st.latest))
	copy(out, st.latest)
	return out
}

// LatestRisk returns the cached Monte Carlo risk simulation from a tenant's most
// recent pass - so the dashboard never triggers a fresh simulation per poll.
func (s *Service) LatestRisk(tenant string) RiskSimulation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st := s.states[graph.NormalizeTenant(tenant)]; st != nil {
		return st.risk
	}
	return RiskSimulation{}
}

// Status is a cheap snapshot of a tenant's analysis state, for clients that poll
// to decide whether a full refetch is needed (avoids re-sending the whole graph
// every few seconds).
type Status struct {
	Version    int64
	Passes     int64
	Paths      int
	AnalyzedAt time.Time
	// Staleness pruning visibility (zero values when TTL pruning is off).
	PrunedNodes  int
	PrunedEdges  int
	LastPrunedAt time.Time
}

// Status returns the latest analysis status for a tenant.
func (s *Service) Status(tenant string) Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st := s.states[graph.NormalizeTenant(tenant)]; st != nil {
		return Status{
			Version: st.lastVersion, Passes: st.passes, Paths: len(st.latest), AnalyzedAt: st.analyzedAt,
			PrunedNodes: st.prunedNodes, PrunedEdges: st.prunedEdges, LastPrunedAt: st.lastPrunedAt,
		}
	}
	return Status{}
}

// Violations returns the invariant violations from a tenant's latest pass.
func (s *Service) Violations(tenant string) []policy.Violation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.states[graph.NormalizeTenant(tenant)]
	if st == nil {
		return nil
	}
	out := make([]policy.Violation, len(st.violations))
	copy(out, st.violations)
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
	for _, tenant := range s.manager.Tenants() {
		s.runTenant(ctx, tenant)
	}
}

func (s *Service) runTenant(ctx context.Context, tenant string) {
	store, err := s.manager.For(ctx, tenant)
	if err != nil {
		slog.Error("analyzer: store unavailable", "tenant", tenant, "err", err)
		return
	}

	s.mu.Lock()
	st := s.states[tenant]
	if st == nil {
		st = &tenantState{}
		s.states[tenant] = st
	}
	s.mu.Unlock()

	// Staleness pruning runs before change-detection: assets go stale by the
	// passage of time, not by new writes, so a pass that would otherwise be
	// skipped (no writes) still needs to prune. A prune that removed anything
	// forces the recompute below (it bumps the store version via VersionedStore).
	pruned := s.maybePrune(ctx, tenant, store, st)

	// Change detection: skip when nothing was written since the last pass - but
	// force a periodic rescan so a replica that didn't ingest the change (its
	// per-process write counter wouldn't move) can't serve a stale cache forever.
	if v, ok := any(store).(versioner); ok {
		cur := v.Version()
		if st.hasRun && cur == st.lastVersion && st.skips < forceRescanEvery && pruned == 0 {
			st.skips++
			// The graph is steady, so don't recompute - but keep the exposure trend
			// continuous by sampling the cached posture (coalesced, flushes ~1/min).
			if s.history != nil {
				s.mu.RLock()
				n, rp := len(st.latest), st.risk.AnyCompromiseProbability*100
				s.mu.RUnlock()
				s.history.SampleTrend(tenant, n, rp)
			}
			return
		}
		st.lastVersion = cur
		st.skips = 0
	}

	start := time.Now()
	snap, err := s.acquireSnapshot(ctx, tenant, store, st, pruned > 0)
	if err != nil {
		slog.Error("analyzer: snapshot failed", "tenant", tenant, "err", err)
		return
	}
	metrics.AnalyzerGraphNodes.WithLabelValues(tenant).Set(float64(len(snap.Nodes)))
	metrics.AnalyzerGraphEdges.WithLabelValues(tenant).Set(float64(len(snap.Edges)))
	// Critical paths via the in-process Dijkstra (default) or, when opted in, the
	// DB-side Cypher finder. The snapshot is needed regardless for the policy
	// invariants and the Monte Carlo risk model below.
	pfStart := time.Now()
	paths := CriticalPathsVia(ctx, store, snap, s.maxHops, s.dbPaths)
	metrics.AnalyzerPathfindSeconds.Observe(time.Since(pfStart).Seconds())
	// Triage: assign each path a composite priority and lead with the highest, so
	// the dashboard's default view (and attackPaths(limit:N)) is the actionable
	// Top-N, not a wall of every reachable route.
	Prioritize(paths)

	var violations []policy.Violation
	if s.policy != nil {
		violations = s.policy.Evaluate(snap)
	}
	// Quantified risk is computed once per pass and cached, so the dashboard
	// reads it without triggering a fresh Monte Carlo on every poll.
	risk := SimulateRisk(snap, DefaultRiskIterations, riskSeed)

	metrics.AnalyzerPasses.Inc()
	metrics.AnalyzerPassSeconds.Observe(time.Since(start).Seconds())
	metrics.AnalyzerCriticalPaths.WithLabelValues(tenant).Set(float64(len(paths)))

	// Drift: diff against the previous pass (skip the first, where everything is
	// "new"), then alert.
	s.mu.Lock()
	prev := st.latest
	firstPass := !st.hasRun
	st.latest = paths
	st.risk = risk
	st.violations = violations
	st.analyzedAt = time.Now()
	st.passes++
	st.hasRun = true
	s.mu.Unlock()

	// Temporal history: fold this pass into the per-path lifecycle (age, MTTR,
	// reopens) and the posture trend. Recorded on every replica (it's derived,
	// in-process state the API reads) - only persistence may race in a multi-
	// replica deploy, and that's last-write-wins, not corruption.
	if s.history != nil {
		obs := make([]history.Observation, len(paths))
		for i, p := range paths {
			obs[i] = history.Observation{ID: p.ID, Route: routeOf(p), Score: p.Score}
		}
		s.history.ObservePass(tenant, obs, risk.AnyCompromiseProbability*100)
	}

	// External side-effects (drift alerts, PR comments) are at-most-once across
	// the fleet: only the leader fires them, so adding replicas never duplicates
	// outbound notifications. Every replica still updated its own cache above.
	isLeader := s.leader.IsLeader(ctx)

	if !firstPass && isLeader {
		if drift := diffPaths(tenant, prev, paths); !drift.Empty() {
			notify.LogDrift(drift)
			go func() {
				if err := s.notifier.Notify(context.WithoutCancel(ctx), drift); err != nil {
					slog.Warn("drift alert failed", "tenant", tenant, "err", err)
				}
			}()
		}
	}

	slog.Info("analyzer pass complete", "tenant", tenant,
		"nodes", len(snap.Nodes), "edges", len(snap.Edges),
		"critical_paths", len(paths), "policy_violations", len(violations))

	for _, v := range violations {
		slog.Warn("policy invariant violated", "tenant", tenant, "id", v.InvariantID, "severity", v.Severity)
	}

	// The sink posts PR/MR comments - also leader-only, at most once per fleet.
	if isLeader && s.sink != nil && len(paths) > 0 {
		s.sink.OnCriticalPaths(ctx, paths)
	}
}

// fullSnapshotEvery bounds how many consecutive incremental passes run before a
// full re-read rebuilds the cache from scratch - a self-healing safety net so any
// drift between the resident cache and the store (a missed delta, a clock skew on
// the last_seen watermark) can't persist beyond this many passes.
const fullSnapshotEvery = 20

// acquireSnapshot returns the graph the pass will reason over, either by reading
// the whole graph (the default) or, when incremental mode is on and the store
// supports deltas, by patching the resident cache with just the elements observed
// since the last pass. It falls back to a full read whenever correctness needs it:
// the first pass, right after a prune (deltas carry no deletions), on the periodic
// rebuild, on any delta error, or for a store without delta support.
func (s *Service) acquireSnapshot(ctx context.Context, tenant string, store graph.Store, st *tenantState, pruned bool) (graph.Snapshot, error) {
	start := time.Now()
	// Capture the watermark BEFORE the read so the next delta re-fetches anything
	// written during this read too (idempotent upserts make the overlap harmless) -
	// no write can slip through the gap between the read and the watermark.
	watermark := start.Unix()

	ds, canDelta := graph.AsDeltaStore(store)
	full := !s.incremental || !canDelta || !st.cacheValid || pruned || st.passesSinceFull >= fullSnapshotEvery

	if !full {
		d, err := ds.SnapshotSince(ctx, st.snapWatermark)
		if err != nil {
			slog.Warn("analyzer: delta snapshot failed, falling back to full read", "tenant", tenant, "err", err)
			full = true
		} else {
			for _, n := range d.Nodes {
				st.cacheNodes[n.ID] = n
			}
			for _, e := range d.Edges {
				st.cacheEdges[edgeID{e.Type, e.From, e.To}] = e
			}
			st.snapWatermark = watermark
			st.passesSinceFull++
			metrics.AnalyzerSnapshots.WithLabelValues("delta").Inc()
			metrics.AnalyzerSnapshotSeconds.Observe(time.Since(start).Seconds())
			return materializeSnapshot(st), nil
		}
	}

	snap, err := store.Snapshot(ctx)
	if err != nil {
		return graph.Snapshot{}, err
	}
	// Only keep the graph resident (and thus reusable as a delta base) when
	// incremental mode is on - otherwise a full read every pass is the contract and
	// holding the cache would just waste memory.
	if s.incremental {
		st.cacheNodes = make(map[string]ontology.Node, len(snap.Nodes))
		for _, n := range snap.Nodes {
			st.cacheNodes[n.ID] = n
		}
		st.cacheEdges = make(map[edgeID]ontology.Edge, len(snap.Edges))
		for _, e := range snap.Edges {
			st.cacheEdges[edgeID{e.Type, e.From, e.To}] = e
		}
		st.cacheValid = true
		st.snapWatermark = watermark
		st.passesSinceFull = 0
	}
	metrics.AnalyzerSnapshots.WithLabelValues("full").Inc()
	metrics.AnalyzerSnapshotSeconds.Observe(time.Since(start).Seconds())
	return snap, nil
}

// materializeSnapshot flattens the resident cache maps into the slice-shaped
// Snapshot the finder/policy/risk layers consume.
func materializeSnapshot(st *tenantState) graph.Snapshot {
	snap := graph.Snapshot{
		Nodes: make([]ontology.Node, 0, len(st.cacheNodes)),
		Edges: make([]ontology.Edge, 0, len(st.cacheEdges)),
	}
	for _, n := range st.cacheNodes {
		snap.Nodes = append(snap.Nodes, n)
	}
	for _, e := range st.cacheEdges {
		snap.Edges = append(snap.Edges, e)
	}
	return snap
}

// maybePrune removes stale graph elements for a tenant when a TTL is configured,
// throttled to s.pruneEvery and gated on leadership so multiple replicas don't
// race on the same deletes. It returns the number of elements removed (0 when
// pruning is off, not due, this replica isn't leader, or nothing was stale).
func (s *Service) maybePrune(ctx context.Context, tenant string, store graph.Store, st *tenantState) int {
	if s.ttl <= 0 || !s.leader.IsLeader(ctx) {
		return 0
	}
	now := time.Now()
	if !st.lastPrune.IsZero() && now.Sub(st.lastPrune) < s.pruneEvery {
		return 0
	}
	st.lastPrune = now

	pruner, ok := graph.AsPruner(store)
	if !ok {
		return 0 // store can't prune (e.g. a bare custom Store); nothing to do
	}
	cutoff := now.Add(-s.ttl)
	stats, err := pruner.Prune(ctx, cutoff)
	if err != nil {
		slog.Warn("graph prune failed", "tenant", tenant, "err", err)
		return 0
	}
	removed := stats.Nodes + stats.Edges
	if removed > 0 {
		metrics.GraphPrunedNodes.Add(float64(stats.Nodes))
		metrics.GraphPrunedEdges.Add(float64(stats.Edges))
		s.mu.Lock()
		st.prunedNodes += stats.Nodes
		st.prunedEdges += stats.Edges
		st.lastPrunedAt = now
		s.mu.Unlock()
		slog.Info("pruned stale graph elements", "tenant", tenant,
			"nodes", stats.Nodes, "edges", stats.Edges, "older_than", cutoff.UTC().Format(time.RFC3339))
	}
	return removed
}

// diffPaths computes which critical paths appeared/resolved between two passes.
func diffPaths(tenant string, prev, cur []AttackPath) notify.DriftEvent {
	prevIDs := map[string]bool{}
	for _, p := range prev {
		prevIDs[p.ID] = true
	}
	curIDs := map[string]bool{}
	for _, p := range cur {
		curIDs[p.ID] = true
	}
	ev := notify.DriftEvent{Tenant: tenant}
	for _, p := range cur {
		if !prevIDs[p.ID] {
			ev.Appeared = append(ev.Appeared, pathSummary(p))
		}
	}
	for _, p := range prev {
		if !curIDs[p.ID] {
			ev.Resolved = append(ev.Resolved, pathSummary(p))
		}
	}
	return ev
}

// routeOf renders a path as "seed → … → jewel" for human-readable history.
func routeOf(p AttackPath) string {
	names := make([]string, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		names = append(names, n.Name)
	}
	return strings.Join(names, " → ")
}

func pathSummary(p AttackPath) notify.PathSummary {
	names := make([]string, 0, len(p.Nodes))
	kev := false
	for _, n := range p.Nodes {
		names = append(names, n.Name)
		if n.Label == ontology.LabelCVE && n.Bool(ontology.PropKEV) {
			kev = true
		}
	}
	return notify.PathSummary{
		ID: p.ID, Route: strings.Join(names, " → "), Score: p.Score,
		RuntimeConfirmed: p.RuntimeConfirmed, KEV: kev,
	}
}
