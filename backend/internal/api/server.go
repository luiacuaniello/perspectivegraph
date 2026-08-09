package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
	"github.com/graphql-go/handler"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/clientip"
	"github.com/luiacuaniello/perspectivegraph/internal/exportsign"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/internal/ratelimit"
	"github.com/luiacuaniello/perspectivegraph/internal/reqid"
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
)

const (
	// maxQueryDepth caps GraphQL selection-set nesting: deeply-nested queries
	// are a classic GraphQL DoS vector. The schema is acyclic and the deepest
	// legitimate query (incl. GraphiQL introspection) stays well under this.
	maxQueryDepth = 15
	// maxQuerySelections caps the TOTAL field resolutions one document may request.
	// Depth is not a budget on its own: a three-level query that aliases the same
	// field ten thousand times is shallow, legal, and ten thousand resolutions. A body
	// limit blunts that but does not bound it - at 256 KiB an alias costs ~20 bytes,
	// so roughly 13k of them fit.
	//
	// 2000 is about five times the largest thing the dashboard asks for (its entire
	// client, every query combined, is under 400 selections) against a schema of 252
	// fields, so it has no effect on real use.
	maxQuerySelections = 2000
	// maxBodyBytes caps the request body (query + variables) to blunt
	// alias-amplification and oversized payloads.
	maxBodyBytes = 256 << 10 // 256 KiB
)

// WithMetricsElsewhere removes GET /metrics from the API's mux, for deployments that
// serve it on a separate listener instead.
//
// Metrics are open and unthrottled by design so a scrape never starves, but several
// series carry a `tenant` label - analyzer_critical_paths, analyzer_graph_nodes,
// analyzer_graph_edges - so on a reachable API port they let anyone enumerate tenants and
// read each one's current posture. That is aggregate, but "which tenants exist and which
// is worst off right now" is the shape of a targeting signal.
//
// Off by default: /metrics on the API port is declared stable surface in
// docs/API-STABILITY.md, and moving it silently would break every existing scrape config.
func (a *API) WithMetricsElsewhere(elsewhere bool) *API {
	a.metricsElsewhere = elsewhere
	return a
}

// WithDegraded marks the API as serving in a reduced mode, which makes /healthz fail so
// an orchestrator stops routing to it. The reason is the human-readable cause, e.g. the
// graph store having fallen back to memory because Apache AGE was unreachable. An empty
// reason (the default) means healthy.
//
// It is deliberately NOT set for a deployment that runs on the in-memory store BY DESIGN:
// that is the demo profile working as intended, not a failure.
func (a *API) WithDegraded(reason string) *API {
	a.degraded = reason
	return a
}

// WithRateLimit caps API requests per client IP. Returns the API for chaining;
// a nil limiter is a no-op.
func (a *API) WithRateLimit(l *ratelimit.Limiter) *API {
	a.limiter = l
	return a
}

// WithClientIP sets how the API identifies a client for the brute-force lockout and the
// audit trail. Nil (the default) trusts no proxy and uses the connecting peer. Pass the
// SAME resolver the rate limiter got: the two controls disagreeing is what let a spoofed
// X-Forwarded-For evade the lockout.
func (a *API) WithClientIP(r *clientip.Resolver) *API {
	a.ips = r
	return a
}

// WithCORSOrigins sets the browser origins allowed to call the API cross-origin.
// A single "*" allows any origin (opt-in); an empty list disables CORS entirely
// (same-origin only). Returns the API for chaining.
func (a *API) WithCORSOrigins(origins []string) *API {
	a.corsOrigins = origins
	return a
}

// WithExportSigner attaches an Ed25519 signer so OSCAL/SIEM exports carry a
// detached signature consumers can verify. A nil signer leaves exports unsigned.
// Returns the API for chaining.
func (a *API) WithExportSigner(s *exportsign.Signer) *API {
	a.exportSigner = s
	return a
}

// WithAbuseWatchers attaches the exfiltration detector (bulk attack-map reads)
// and the auth brute-force lockout guard. Nil/zero-threshold watchers are no-ops.
// Returns the API for chaining.
func (a *API) WithAbuseWatchers(exfil, authGuard *secwatch.Watcher) *API {
	a.exfil = exfil
	a.authGuard = authGuard
	return a
}

// Handler builds the HTTP routes for the BFF: a GraphQL endpoint (with the
// in-browser GraphiQL playground enabled), a health check and Prometheus
// /metrics. CORS is opened for the local Vite dev server.
func (a *API) Handler() (http.Handler, error) {
	schema, err := a.Schema()
	if err != nil {
		return nil, err
	}

	gql := handler.New(&handler.Config{
		Schema: &schema,
		Pretty: true,
		// The in-browser playground is open by design; disable it when the API
		// is authenticated so a secured deployment doesn't expose it.
		GraphiQL:   !a.authEnabled(),
		Playground: false,
	})

	mux := http.NewServeMux()
	// Health has to be able to say no, or it is decoration. It used to return 200
	// unconditionally, which meant the Kubernetes readiness probe only ever proved the
	// HTTP server was listening. Combined with the in-memory fallback that engaged when
	// Apache AGE was unreachable, a backend serving an empty volatile graph reported
	// healthy and kept receiving traffic - and an empty graph answers "no attack paths",
	// which reads as good news. A degraded engine now fails the probe and is taken out
	// of rotation, because withholding an answer beats returning a falsely reassuring one.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { a.writeHealth(w) })
	// Prometheus metrics - open and unthrottled so scraping never starves. Served here
	// unless METRICS_ADDR gave them their own listener; see WithMetricsElsewhere.
	if !a.metricsElsewhere {
		mux.Handle("GET /metrics", metrics.Handler())
	}
	// Public auth config - necessarily open: it tells an unauthenticated SPA how to
	// authenticate (token vs SSO). Secret-free (only the IdP's public coordinates).
	mux.HandleFunc("GET /auth/config", a.handleAuthConfig)

	// secured wraps a data handler with: rate limit → auth (when enabled) →
	// per-handler request counting. The limiter is outermost so floods are
	// dropped before any work.
	secured := func(name string, h http.Handler) http.Handler {
		if a.authEnabled() {
			h = auth.RequireRole(a.authn, auth.RoleViewer, a.audit, a.authGuard, a.ips, h)
		}
		return a.limiter.Middleware(counting(name, h))
	}

	// Guard the query (depth + body size), then memoize one snapshot per request.
	mux.Handle("/graphql", secured("graphql", withQueryGuard(withSnapshotCache(gql, a.manager))))
	// SIEM enrichment export (NDJSON) and OSCAL assessment-results, same scoping.
	mux.Handle("GET /export/ndjson", secured("export_ndjson", http.HandlerFunc(a.exportNDJSON)))
	mux.Handle("GET /export/oscal", secured("export_oscal", http.HandlerFunc(a.exportOSCAL)))
	// The export-signing public key is, by definition, public: open so any
	// consumer can fetch it to verify a signed export's detached signature.
	mux.Handle("GET /export/pubkey", a.limiter.Middleware(http.HandlerFunc(a.exportPubKey)))

	// Triage/suppression board. GET needs viewer (enforced by secured); the
	// write handlers additionally require admin (checked inside, when auth is on).
	mux.Handle("GET /suppressions", secured("suppressions_list", http.HandlerFunc(a.listSuppressions)))
	mux.Handle("POST /suppressions", secured("suppressions_put", http.HandlerFunc(a.putSuppression)))
	mux.Handle("DELETE /suppressions/{pathID}", secured("suppressions_delete", http.HandlerFunc(a.deleteSuppression)))

	// Remediation ticketing - open/list/close owned work for a path. GET needs
	// viewer; the writes additionally require admin (checked inside, when auth on).
	mux.Handle("GET /tickets", secured("tickets_list", http.HandlerFunc(a.listTickets)))
	mux.Handle("POST /tickets", secured("tickets_create", http.HandlerFunc(a.createTicket)))
	mux.Handle("POST /tickets/{id}/close", secured("tickets_close", http.HandlerFunc(a.closeTicket)))
	// Remediation-as-PR: open a pull request with a path's generated fix.
	mux.Handle("POST /remediation/pr", secured("remediation_pr", http.HandlerFunc(a.openRemediationPR)))
	// AI-native layer (self-gated on ANTHROPIC_API_KEY): NL query, exec summary,
	// and plain-English path explanation.
	mux.Handle("GET /ai/summary", secured("ai_summary", http.HandlerFunc(a.handleAISummary)))
	mux.Handle("POST /ai/query", secured("ai_query", http.HandlerFunc(a.handleAIQuery)))
	mux.Handle("POST /ai/explain", secured("ai_explain", http.HandlerFunc(a.handleAIExplain)))

	// Red-team / BAS validation verdicts + precision/recall. GET needs viewer;
	// writes additionally require admin (checked inside, when auth is on).
	mux.Handle("GET /validations", secured("validations_list", http.HandlerFunc(a.listValidations)))
	mux.Handle("POST /validations", secured("validations_put", http.HandlerFunc(a.putValidation)))
	mux.Handle("POST /validations/import", secured("validations_import", http.HandlerFunc(a.importValidations)))
	mux.Handle("DELETE /validations/{id}", secured("validations_delete", http.HandlerFunc(a.deleteValidation)))

	// reqid is OUTERMOST so every request has an id, including the ones rejected by
	// CORS, the rate limiter or auth - those are exactly the ones someone asks about.
	return reqid.Middleware(a.withCORS(mux)), nil
}

// counting records the response status class for a named handler.
func counting(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		metrics.Count(name, sw.status)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// ── GraphQL query guard (depth + body-size limit) ───────────────────

func withQueryGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GET (GraphiQL UI, or ?query=) and POST (the standard transport).
		var query string
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, `{"errors":[{"message":"request body too large"}]}`, http.StatusRequestEntityTooLarge)
				return
			}
			// Restore the body for the downstream handler.
			r.Body = io.NopCloser(bytes.NewReader(body))
			var params struct {
				Query string `json:"query"`
			}
			_ = json.Unmarshal(body, &params) // non-JSON bodies fall through to the handler's own error
			query = params.Query
		} else {
			query = r.URL.Query().Get("query")
		}

		if query != "" {
			// A parse failure is deliberately NOT rejected here: this uses the same
			// parser the executor does, so anything unparseable fails downstream on its
			// own terms, with a proper GraphQL error instead of ours.
			if c, err := queryCost(query); err == nil {
				var msg string
				switch {
				case c.depth > maxQueryDepth:
					msg = "query exceeds maximum depth"
				case c.selections > maxQuerySelections:
					msg = "query exceeds maximum complexity"
				}
				if msg != "" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, `{"errors":[{"message":"`+msg+`"}]}`)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// cost is what one selection set asks the server to do: how deep it nests, and how many
// field resolutions it adds up to. Depth alone is not a budget - a document three levels
// deep that aliases the same expensive field ten thousand times passes every depth check
// there is and still resolves it ten thousand times.
type cost struct {
	depth      int
	selections int
}

// queryCost parses a GraphQL document and returns the worst depth and the total field
// count across its operations, expanding fragment spreads.
//
// Fragment costs are MEMOISED, and that is a security property rather than an
// optimisation. The previous version re-descended into every spread at every use site,
// which is exponential on a document with no cycle at all:
//
//	query { ...F0 }
//	fragment F0 on Query { ...F1 ...F1 }
//	fragment F1 on Query { ...F2 ...F2 }   … and so on
//
// Thirty such fragments fit in 1233 bytes and cost 2^30 descents - measured at over ten
// seconds before this change, against 4.4 s at twenty-five and 125 ms at twenty. The
// cycle guard did not help because there is no cycle; each fragment is simply used twice.
// So the guard meant to stop a denial of service WAS one, reachable by anyone who could
// reach the endpoint with a credential - and by anyone at all in the demo profile, where
// auth is off. Memoising makes it linear in the document.
func queryCost(query string) (cost, error) {
	doc, err := parser.Parse(parser.ParseParams{
		Source: source.NewSource(&source.Source{Body: []byte(query)}),
	})
	if err != nil {
		return cost{}, err
	}
	fragments := map[string]*ast.FragmentDefinition{}
	for _, def := range doc.Definitions {
		if fd, ok := def.(*ast.FragmentDefinition); ok && fd.Name != nil {
			fragments[fd.Name.Value] = fd
		}
	}

	memo := map[string]cost{}
	visiting := map[string]bool{}
	var worst cost
	for _, def := range doc.Definitions {
		op, ok := def.(*ast.OperationDefinition)
		if !ok {
			continue
		}
		c := selectionSetCost(op.SelectionSet, fragments, memo, visiting)
		if c.depth > worst.depth {
			worst.depth = c.depth
		}
		// The MOST EXPENSIVE operation, not the sum of them. A GraphQL request executes
		// exactly one operation - whichever `operationName` selects - so charging for
		// all of them would reject documents that are perfectly legal and cheap to
		// serve. GraphiQL sends exactly that: the whole editor buffer, one operation
		// chosen. Nothing is given away by taking the max, because the operations that
		// are not selected never resolve a field; the only cost they add is parsing,
		// which the body-size limit already bounds.
		if c.selections > worst.selections {
			worst.selections = c.selections
		}
	}
	return worst, nil
}

func selectionSetCost(ss *ast.SelectionSet, fragments map[string]*ast.FragmentDefinition, memo map[string]cost, visiting map[string]bool) cost {
	if ss == nil {
		return cost{}
	}
	var out cost
	for _, sel := range ss.Selections {
		var c cost
		switch s := sel.(type) {
		case *ast.Field:
			child := selectionSetCost(s.SelectionSet, fragments, memo, visiting)
			// Each field - each ALIAS of a field - is one resolution of its own, and a
			// resolution is charged what it actually costs (see fieldWeight).
			c = cost{depth: 1 + child.depth, selections: fieldWeight(s) + child.selections}
		case *ast.InlineFragment:
			c = selectionSetCost(s.SelectionSet, fragments, memo, visiting)
		case *ast.FragmentSpread:
			c = fragmentCost(s.Name.Value, fragments, memo, visiting)
		}
		if c.depth > out.depth {
			out.depth = c.depth
		}
		out.selections += c.selections
		// Stop counting once the budget is already blown: the counter must not become
		// the cost it exists to bound.
		if out.selections > maxQuerySelections {
			return out
		}
	}
	return out
}

// Per-field cost weights.
//
// Counting every field as 1 assumes they all cost about the same, and in this schema they
// emphatically do not: `aiEnabled` returns a bool from memory, while `riskSimulation`
// runs up to 50 000 Monte Carlo trials over the whole graph. Under a flat count, 200
// aliases of the expensive one came to ~400 "selections" - a fifth of the budget - and
// took 91 seconds of CPU on one unauthenticated 13 KB request. The budget was never the
// binding constraint, so the guard let through exactly the amplification its own comment
// warns about.
//
// The weights are in the same units as the budget, so N of a field is admissible only
// while N·weight stays under maxQuerySelections. Charging by NAME is deliberate: this
// runs before execution, on a parsed document with no schema attached, so a type-aware
// price is not available here. A cheap field that happens to share a name with an
// expensive one is over-charged, which is the safe direction to be wrong in.
const (
	// weightSimulation prices one full-graph Monte Carlo run (~0.4 s measured at the
	// 50 000-iteration cap). 200 leaves room for ten per document, which is generous for
	// anything a human asks and far short of an amplifier.
	weightSimulation = 200
	// weightKShortest prices one Yen enumeration, superlinear in the graph and linear in
	// a k the caller chooses.
	weightKShortest = 200
	// weightVerification prices a remediation's what-if proof: two simulations, but at
	// verifyIterations (800) rather than the cap. Deliberately modest - the dashboard
	// asks for `verification` across a whole plan in one document, and pricing it like a
	// full simulation would reject the product's own legitimate query.
	weightVerification = 5
)

// fieldWeight returns what one resolution of f costs, in the budget's units.
func fieldWeight(f *ast.Field) int {
	if f.Name == nil {
		return 1
	}
	switch f.Name.Value {
	case "riskSimulation":
		// Bare `riskSimulation` is served from the simulation the analyzer already ran
		// for this pass - a map lookup, genuinely cheap, and what the dashboard polls.
		// Only an explicit iterations/seed recomputes, so only that is charged. Passing
		// `iterations: 0` is charged too, which costs the caller nothing they need.
		if hasArg(f, "iterations") || hasArg(f, "seed") {
			return weightSimulation
		}
		return 1
	case "whatIf":
		return weightSimulation
	case "kShortestPaths":
		return weightKShortest
	case "verification":
		return weightVerification
	}
	return 1
}

func hasArg(f *ast.Field, name string) bool {
	for _, a := range f.Arguments {
		if a.Name != nil && a.Name.Value == name {
			return true
		}
	}
	return false
}

func fragmentCost(name string, fragments map[string]*ast.FragmentDefinition, memo map[string]cost, visiting map[string]bool) cost {
	if c, ok := memo[name]; ok {
		return c
	}
	if visiting[name] { // cyclic fragment - poison it rather than recurse forever
		return cost{depth: maxQueryDepth + 1, selections: maxQuerySelections + 1}
	}
	fd, ok := fragments[name]
	if !ok {
		return cost{} // undefined fragment; the executor rejects it on its own terms
	}
	visiting[name] = true
	c := selectionSetCost(fd.SelectionSet, fragments, memo, visiting)
	delete(visiting, name)
	memo[name] = c
	return c
}

// withCORS echoes Access-Control-Allow-Origin only for an allow-listed Origin
// (or "*" when the operator opts into a wildcard). This tool is a map of how to
// attack the org, so a permissive default would let any web page a logged-in
// analyst visits probe the API - the allowlist closes that.
func (a *API) withCORS(next http.Handler) http.Handler {
	allowAll := false
	allowed := make(map[string]bool, len(a.corsOrigins))
	for _, o := range a.corsOrigins {
		if o == "*" {
			allowAll = true
		}
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		switch {
		case allowAll:
			w.Header().Set("Access-Control-Allow-Origin", "*")
		case origin != "" && allowed[origin]:
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── per-request snapshot memoization ────────────────────────────────

type snapCtxKey struct{}

// snapshotLoader memoizes one store snapshot for the lifetime of a request,
// scoped to the request's tenant: a dashboard query asking for posture + graph
// used to scan the store twice.
type snapshotLoader struct {
	manager *graph.Manager
	once    sync.Once
	snap    graph.Snapshot
	err     error
}

func (l *snapshotLoader) load(ctx context.Context) (graph.Snapshot, error) {
	l.once.Do(func() {
		store, err := l.manager.For(ctx, tenantOf(ctx))
		if err != nil {
			l.err = err
			return
		}
		l.snap, l.err = store.Snapshot(ctx)
	})
	return l.snap, l.err
}

func withSnapshotCache(next http.Handler, manager *graph.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), snapCtxKey{}, &snapshotLoader{manager: manager})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// rawSnapshot resolves through the per-request loader when present (HTTP path),
// falling back to a direct tenant store read (tests, embedded use). It is the
// full tenant graph; a.snapshot wraps it with per-principal app scoping.
func (a *API) rawSnapshot(ctx context.Context) (graph.Snapshot, error) {
	if l, ok := ctx.Value(snapCtxKey{}).(*snapshotLoader); ok {
		return l.load(ctx)
	}
	store, err := a.manager.For(ctx, tenantOf(ctx))
	if err != nil {
		return graph.Snapshot{}, err
	}
	return store.Snapshot(ctx)
}

// writeHealth is the body of GET /healthz, split out so it can be tested without
// standing up the whole router.
func (a *API) writeHealth(w http.ResponseWriter) {
	if a.degraded != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "degraded: "+a.degraded+"\n")
		return
	}
	// The startup reason above is a judgement made ONCE, at construction. On its own it
	// let the process report "ok" for as long as it stayed up while its database was
	// gone and every query returned an error - so an orchestrator kept routing to it,
	// and any alert built on this probe never fired. Readiness has to be asked now.
	if err := a.storeReachable(); err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "graph store unreachable: "+err.Error()+"\n")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// readinessTTL is how long a store Ping is trusted. Long enough that a kubelet probing
// every few seconds does not put a query on the database each time; short enough that an
// outage is reflected within one probe interval.
const readinessTTL = 3 * time.Second

// readinessTimeout bounds the Ping. A database that accepts the connection and then
// stops answering must not hold the probe open past the kubelet's own timeout, or the
// probe neither succeeds nor fails and the pod sits in limbo.
const readinessTimeout = 2 * time.Second

// storeReachable reports whether the graph store answers, memoised for readinessTTL.
func (a *API) storeReachable() error {
	a.readyMu.Lock()
	defer a.readyMu.Unlock()
	if a.readyOnce && time.Since(a.readyAt) < readinessTTL {
		return a.readyErr
	}

	if a.manager == nil {
		// No store to ask. Only reachable from a unit test that built an API directly;
		// a running server always has one. Handled rather than dereferenced, because a
		// panic in the probe handler is the worst possible place for one.
		a.readyOnce, a.readyAt, a.readyErr = true, time.Now(), nil
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), readinessTimeout)
	defer cancel()
	store, err := a.manager.For(ctx, graph.DefaultTenant)
	if err == nil {
		err = store.Ping(ctx)
	}

	a.readyOnce, a.readyAt, a.readyErr = true, time.Now(), err
	return err
}
