// Package api is the Backend-For-Frontend. It exposes a GraphQL schema so the
// dashboard can ask for exactly the slice of the graph it needs (attack paths,
// posture summary, policy violations, full-text search, or the raw node/edge
// view for Cytoscape).
package api

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/graphql-go/graphql"
	"github.com/luiacuaniello/perspectivegraph/internal/action"
	"github.com/luiacuaniello/perspectivegraph/internal/ai"
	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/attck"
	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/broker"
	"github.com/luiacuaniello/perspectivegraph/internal/clientip"
	"github.com/luiacuaniello/perspectivegraph/internal/coverage"
	"github.com/luiacuaniello/perspectivegraph/internal/exportsign"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
	"github.com/luiacuaniello/perspectivegraph/internal/ratelimit"
	"github.com/luiacuaniello/perspectivegraph/internal/remediation"
	"github.com/luiacuaniello/perspectivegraph/internal/search"
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// API wires the data sources the resolvers read from. Queries are scoped to the
// caller's tenant (from the authenticated principal; the default tenant when
// auth is open).
type API struct {
	// readiness memoises the last store Ping, so a probe every few seconds does not
	// become a database query per probe. See (*API).storeReachable.
	readyMu   sync.Mutex
	readyAt   time.Time
	readyErr  error
	readyOnce bool

	coverage    *coverage.Store
	manager     *graph.Manager
	analyzer    *analyzer.Service
	search      search.Indexer
	authn       auth.Authenticator
	audit       audit.Recorder
	limiter     *ratelimit.Limiter
	suppress    suppress.Suppressions
	history     history.Temporal
	ticket      ticket.Tickets
	validation  validation.Verdicts
	corsOrigins []string
	// degraded, when non-empty, is why this instance serves in a reduced mode;
	// /healthz fails while it is set. See WithDegraded.
	degraded string
	// metricsElsewhere drops GET /metrics from this mux; see WithMetricsElsewhere.
	metricsElsewhere bool
	exportSigner     *exportsign.Signer
	exfil            *secwatch.Watcher  // exfiltration detector (attack-map bulk reads)
	ips              *clientip.Resolver // how per-IP controls identify a client
	introspection    string             // "on" | "off" | "" (follow the auth posture)
	authGuard        *secwatch.Watcher  // auth brute-force lockout
	authInfo         AuthInfo           // public auth config for the SPA login gate
	prOpener         action.PROpener    // opens remediation pull requests (nil → disabled)
	ai               ai.Client          // AI-native layer (nil/Nop → disabled)
	aiLimiter        *ratelimit.Limiter // per-client cap on /ai/* (nil → none)
	heavySlots       chan struct{}      // process-wide cap on heavy analyses; see compute.go
	batches          BatchTracker       // ingest batch progress, for the merge gate (nil → none)
	// The merge gate's POST /gate/impact (gate.go): the collectors that parse a report,
	// by source, and the normalizer a change goes through. nil collectors → disabled.
	gateCollectors map[string]ingestion.Collector
	gateNormalizer func(*graph.Manager) *normalization.Normalizer
}

func New(manager *graph.Manager, svc *analyzer.Service, idx search.Indexer) *API {
	if idx == nil {
		idx = search.Noop{}
	}
	// Default to an in-memory suppression store so triage works out of the box;
	// WithSuppress swaps in a file-backed one when SUPPRESSIONS_PATH is set.
	mem, _ := suppress.New("")
	hist, _ := history.New("")
	tk, _ := ticket.New("", "")
	val, _ := validation.New("")
	return &API{
		manager: manager, analyzer: svc, search: idx, audit: audit.Nop{},
		suppress: mem, history: hist, ticket: tk, validation: val,
		// Sensible default so the dev/demo dashboards work; overridden by
		// WithCORSOrigins from CORS_ALLOWED_ORIGINS.
		corsOrigins: []string{"http://localhost:5173", "http://localhost:3000"},
		heavySlots:  make(chan struct{}, heavyConcurrency()),
	}
}

// WithValidation attaches the red-team/BAS validation store the API reads for
// per-path verdicts and the precision/recall metric. A nil store keeps the
// default in-memory one. Returns the API for chaining.
func (a *API) WithValidation(v validation.Verdicts) *API {
	if v != nil {
		a.validation = v
	}
	return a
}

// WithTickets attaches the remediation ticketing store (file-backed and/or
// webhook-dispatching). A nil store leaves the default in-memory one in place.
// Returns the API for chaining.
func (a *API) WithTickets(t ticket.Tickets) *API {
	if t != nil {
		a.ticket = t
	}
	return a
}

// WithSuppress attaches the (file-backed) triage/suppression store. A nil store
// leaves the default in-memory one in place. Returns the API for chaining.
func (a *API) WithSuppress(s suppress.Suppressions) *API {
	if s != nil {
		a.suppress = s
	}
	return a
}

// WithHistory attaches the temporal store the API reads for path age, MTTR and
// the posture trend. A nil store leaves the default in-memory one in place.
// Returns the API for chaining.
// WithCoverage lets the API report what the engine has actually been fed, so a caller
// can tell "no attack path" apart from "nothing was ever ingested about that". Returns
// the API for chaining; a nil store simply reports no coverage.
func (a *API) WithCoverage(c *coverage.Store) *API {
	a.coverage = c
	return a
}

// BatchTracker reports how much of an ingest batch has reached the graph
// (broker.PublishBatch). The merge gate asks through ingestBatch before trusting a
// verdict, because a pass can run between the messages of one large report.
type BatchTracker interface {
	BatchStatus(ctx context.Context, id string) (broker.BatchStatus, error)
}

// WithIngestBatches attaches the batch tracker; nil leaves ingestBatch answering null.
func (a *API) WithIngestBatches(t BatchTracker) *API {
	a.batches = t
	return a
}

func (a *API) WithHistory(h history.Temporal) *API {
	if h != nil {
		a.history = h
	}
	return a
}

// WithAuth requires a bearer credential (≥ viewer) on the GraphQL endpoint,
// audits access, and disables the in-browser GraphiQL playground. Returns the
// API for chaining.
func (a *API) WithAuth(authn auth.Authenticator, rec audit.Recorder) *API {
	a.authn = authn
	if rec != nil {
		a.audit = rec
	}
	return a
}

func (a *API) authEnabled() bool { return a.authn != nil && a.authn.Enabled() }

// auditView records a *read* of the sensitive "attack map" - the ranked paths,
// the raw graph, or an export - to the tamper-evident audit log, so a deployment
// can answer "who viewed (or exfiltrated) which attack paths". The tool itself is
// a map of how to breach the org, so its reads are governed, not just its writes.
// A no-op unless AUDIT_LOG_PATH is configured (a.audit is then audit.Nop).
func (a *API) auditView(ctx context.Context, action string, fields map[string]any) {
	p := auth.PrincipalFromContext(ctx)
	a.audit.Record(ctx, action, p.Subject, p.Role.String(), p.Tenant, fields)
	// Exfiltration watch: a principal pulling an unusual volume of attack paths
	// (bulk reads/exports) in a short window is the tool's own data walking out the
	// door - fire one alert per principal per cooldown.
	if a.exfil.Enabled() {
		if n := viewCount(fields); n > 0 {
			a.exfil.Observe(p.Subject+"@"+p.Tenant, n)
		}
	}
}

// viewCount sums the "size" of a view from the audit fields, so one OSCAL export
// of 200 paths weighs 200 against the exfil threshold (not 1).
func viewCount(f map[string]any) int {
	n := 0
	for _, k := range []string{"paths", "assets", "count"} {
		if v, ok := f[k].(int); ok {
			n += v
		}
	}
	return n
}

// pathIDsCapped returns up to limit path ids for an audit record, so a large
// result set can't bloat the log while still naming what was seen.
func pathIDsCapped(paths []analyzer.AttackPath, limit int) []string {
	if len(paths) > limit {
		paths = paths[:limit]
	}
	ids := make([]string, 0, len(paths))
	for _, p := range paths {
		ids = append(ids, p.ID)
	}
	return ids
}

// historyView is the resolved shape of the `history` query: the posture trend
// plus the rolled-up temporal stats and whether the store is persistent.
type historyView struct {
	Trend      []history.PosturePoint
	Stats      history.Stats
	Persistent bool
}

// field adapts a typed accessor into a graphql resolver: one generic helper
// instead of a copy per source type.
func field[T any](f func(T) any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) { return f(p.Source.(T)), nil }
}

// maxRiskIterations caps Monte Carlo work per request so a hostile `iterations`
// can't turn a query into a CPU-exhaustion vector.
const maxRiskIterations = 50000

// maxShortestPaths caps k for Yen's algorithm, which is linear in k over a search that
// is itself superlinear in the graph. 200 is far above any real "show me the alternate
// routes" question and far below a number that turns one query into minutes of work.
const maxShortestPaths = 200

// verifyIterations bounds the Monte Carlo work for the per-remediation
// verification, so selecting `verification` on a plan of several fixes stays
// cheap while still giving a meaningful risk delta.
const verifyIterations = 800

// verifyCut closes the remediation loop: it simulates removing the edge a fix
// severs (what-if over the current graph) and reports the proven effect - paths
// eliminated and risk reduction - so the dashboard can show "verified: removes N
// paths" instead of trusting the generator. Returns nil when the fix carries no
// structured cut edge.
func (a *API) verifyCut(ctx context.Context, cut remediation.CutEdge) (any, error) {
	if cut.From == "" || cut.To == "" {
		return nil, nil
	}
	// Read outside the analyses below, for the reason given in riskSimulation.
	snap, err := a.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	// The uncut graph's simulation is the same for every fix, and it is half of each
	// proof's cost, so the request runs it once. It is a call of its own rather than
	// nested in the proof below, which would hold one slot while waiting for another.
	//
	// Point estimates only, here and in the proof: the proof reads nothing else, and the
	// credible band and attacker mixture were ~96% of each simulation's trials.
	point := analyzer.RiskOptions{PointOnly: true}
	base, err := a.heavy(ctx, fmt.Sprintf("riskpoint|%d|%d", verifyIterations, 1), func(ctx context.Context) (any, error) {
		return analyzer.SimulateRiskWith(ctx, snap, verifyIterations, 1, point)
	})
	if err != nil {
		return nil, err
	}
	// Several fixes, and several paths, often cut the same edge: through heavy, the
	// request proves each distinct cut once.
	v, err := a.heavy(ctx, "verify|"+cut.Type+"|"+cut.From+"|"+cut.To, func(ctx context.Context) (any, error) {
		return analyzer.WhatIfFromWith(ctx, snap, base.(analyzer.RiskSimulation),
			[]analyzer.EdgeCut{{From: cut.From, To: cut.To, Type: ontology.EdgeType(cut.Type)}},
			verifyIterations, 1, point)
	})
	if err != nil {
		return nil, err
	}
	res := v.(analyzer.WhatIfResult)
	eliminated := len(res.Before) - len(res.After)
	// Both simulations ran the same trials, so any drop is the cut's doing: a threshold
	// would only hide a real, small effect. It used to be 0.0005 against two independent
	// samples whose difference was noise of ±2.5 points - which verified, half the time, a
	// cut that did nothing.
	expected := res.ExpectedReduction()
	return map[string]any{
		"removedEdges":      res.RemovedEdges,
		"pathsBefore":       len(res.Before),
		"pathsAfter":        len(res.After),
		"pathsEliminated":   eliminated,
		"riskReductionPct":  res.RiskReduction() * 100,
		"expectedReduction": expected,
		"verified":          res.RemovedEdges > 0 && (eliminated > 0 || expected > 0),
	}, nil
}

// resolveNodeRef maps a user-supplied node reference (id or name) to a node id.
// An id wins; otherwise the first name match; otherwise the literal is returned
// so callers may reference ids not present in the current snapshot.
func resolveNodeRef(snap graph.Snapshot, ref string) string {
	if ref == "" {
		return ""
	}
	for _, n := range snap.Nodes {
		if n.ID == ref {
			return ref
		}
	}
	for _, n := range snap.Nodes {
		if n.Name == ref {
			return n.ID
		}
	}
	return ref
}

// parseCuts converts the GraphQL [EdgeCutInput!] argument into analyzer cuts,
// resolving each endpoint reference (id or name) to a node id.
func parseCuts(raw any, resolve func(string) string) []analyzer.EdgeCut {
	list, _ := raw.([]any)
	cuts := make([]analyzer.EdgeCut, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		from, _ := m["from"].(string)
		to, _ := m["to"].(string)
		typ, _ := m["type"].(string)
		cuts = append(cuts, analyzer.EdgeCut{From: resolve(from), To: resolve(to), Type: ontology.EdgeType(typ)})
	}
	return cuts
}

// ── application scoping ─────────────────────────────────────────────
//
// The graph is environment-wide by design; "application" is a view over it. A
// node belongs to app X when its repo_slug (stamped by scanners/CI) or its
// `app` tag (cloud resources) equals X.

func nodeMatchesApp(n ontology.Node, app string) bool {
	if s, _ := n.Properties[ontology.PropRepoSlug].(string); s == app {
		return true
	}
	if s, _ := n.Properties["app"].(string); s == app {
		return true
	}
	return false
}

func nodeMatchesAnyApp(n ontology.Node, apps []string) bool {
	for _, app := range apps {
		if nodeMatchesApp(n, app) {
			return true
		}
	}
	return false
}

func pathMatchesApp(p analyzer.AttackPath, app string) bool {
	return pathMatchesAnyApp(p, []string{app})
}

func pathMatchesAnyApp(p analyzer.AttackPath, apps []string) bool {
	for _, n := range p.Nodes {
		if nodeMatchesAnyApp(n, apps) {
			return true
		}
	}
	return false
}

// filterByApp keeps the connected component(s) around the nodes that belong to
// the app, so the filtered view still shows the app's blast radius.
func filterByApp(snap graph.Snapshot, app string) ([]ontology.Node, []ontology.Edge) {
	return filterByApps(snap, []string{app})
}

// filterByApps keeps the connected component(s) around nodes belonging to any of
// the apps (the union of their blast radii).
func filterByApps(snap graph.Snapshot, apps []string) ([]ontology.Node, []ontology.Edge) {
	adj := map[string][]string{}
	for _, e := range snap.Edges {
		adj[e.From] = append(adj[e.From], e.To)
		adj[e.To] = append(adj[e.To], e.From)
	}
	keep := map[string]bool{}
	var stack []string
	for _, n := range snap.Nodes {
		if nodeMatchesAnyApp(n, apps) {
			stack = append(stack, n.ID)
		}
	}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if keep[id] {
			continue
		}
		keep[id] = true
		stack = append(stack, adj[id]...)
	}

	var nodes []ontology.Node
	for _, n := range snap.Nodes {
		if keep[n.ID] {
			nodes = append(nodes, n)
		}
	}
	var edges []ontology.Edge
	for _, e := range snap.Edges {
		if keep[e.From] && keep[e.To] {
			edges = append(edges, e)
		}
	}
	return nodes, edges
}

// applications lists the distinct app identifiers present in the snapshot.
func applications(snap graph.Snapshot) []string {
	set := map[string]bool{}
	for _, n := range snap.Nodes {
		if s, _ := n.Properties[ontology.PropRepoSlug].(string); s != "" {
			set[s] = true
		}
		if s, _ := n.Properties["app"].(string); s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// paginate slices nodes deterministically (sorted by id) and keeps only the
// edges whose endpoints survive.
func paginate(nodes []ontology.Node, edges []ontology.Edge, limit, offset int) ([]ontology.Node, []ontology.Edge) {
	if limit <= 0 && offset <= 0 {
		return nodes, edges
	}
	sorted := make([]ontology.Node, len(nodes))
	copy(sorted, nodes)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	if offset > len(sorted) {
		offset = len(sorted)
	}
	end := len(sorted)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	page := sorted[offset:end]

	keep := map[string]bool{}
	for _, n := range page {
		keep[n.ID] = true
	}
	var keptEdges []ontology.Edge
	for _, e := range edges {
		if keep[e.From] && keep[e.To] {
			keptEdges = append(keptEdges, e)
		}
	}
	return page, keptEdges
}

// stampedWith reports whether a node carries this pull request's commit context, which
// the trivy and semgrep collectors attach when CI posts their output with slug/pr/sha.
// stampedWith defers to the shared rule so this query and the CI gate's local mode
// cannot drift apart. See ontology.StampedWith.
func stampedWith(props map[string]any, slug, sha string) bool {
	return ontology.StampedWith(props, slug, sha)
}

// stepView is a path's hop with what can only be read from the whole route: its ATT&CK
// technique (attck.ForStep).
type stepView struct {
	analyzer.Step
	technique *attck.Technique
}

func stepViews(p analyzer.AttackPath) []stepView {
	route := make([]ontology.EdgeType, len(p.Steps))
	for i, st := range p.Steps {
		route[i] = st.EdgeType
	}
	out := make([]stepView, len(p.Steps))
	for i, st := range p.Steps {
		out[i] = stepView{Step: st}
		if t, ok := attck.ForStep(route, i); ok {
			out[i].technique = &t
		}
	}
	return out
}
