package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
	"github.com/graphql-go/handler"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/exportsign"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/internal/ratelimit"
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
)

const (
	// maxQueryDepth caps GraphQL selection-set nesting: deeply-nested queries
	// are a classic GraphQL DoS vector. The schema is acyclic and the deepest
	// legitimate query (incl. GraphiQL introspection) stays well under this.
	maxQueryDepth = 15
	// maxBodyBytes caps the request body (query + variables) to blunt
	// alias-amplification and oversized payloads.
	maxBodyBytes = 256 << 10 // 256 KiB
)

// WithRateLimit caps API requests per client IP. Returns the API for chaining;
// a nil limiter is a no-op.
func (a *API) WithRateLimit(l *ratelimit.Limiter) *API {
	a.limiter = l
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
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Prometheus metrics - open and unthrottled so scraping never starves.
	mux.Handle("GET /metrics", metrics.Handler())
	// Public auth config - necessarily open: it tells an unauthenticated SPA how to
	// authenticate (token vs SSO). Secret-free (only the IdP's public coordinates).
	mux.HandleFunc("GET /auth/config", a.handleAuthConfig)

	// secured wraps a data handler with: rate limit → auth (when enabled) →
	// per-handler request counting. The limiter is outermost so floods are
	// dropped before any work.
	secured := func(name string, h http.Handler) http.Handler {
		if a.authEnabled() {
			h = auth.RequireRole(a.authn, auth.RoleViewer, a.audit, a.authGuard, h)
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
	mux.Handle("DELETE /validations/{id}", secured("validations_delete", http.HandlerFunc(a.deleteValidation)))

	return a.withCORS(mux), nil
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
			if depth, err := queryDepth(query); err == nil && depth > maxQueryDepth {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"errors":[{"message":"query exceeds maximum depth"}]}`)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// queryDepth parses a GraphQL document and returns its maximum selection-set
// nesting, resolving fragment spreads (with a cycle guard).
func queryDepth(query string) (int, error) {
	doc, err := parser.Parse(parser.ParseParams{
		Source: source.NewSource(&source.Source{Body: []byte(query)}),
	})
	if err != nil {
		return 0, err
	}
	fragments := map[string]*ast.FragmentDefinition{}
	for _, def := range doc.Definitions {
		if fd, ok := def.(*ast.FragmentDefinition); ok && fd.Name != nil {
			fragments[fd.Name.Value] = fd
		}
	}
	max := 0
	for _, def := range doc.Definitions {
		if op, ok := def.(*ast.OperationDefinition); ok {
			if d := selectionSetDepth(op.SelectionSet, fragments, map[string]bool{}); d > max {
				max = d
			}
		}
	}
	return max, nil
}

func selectionSetDepth(ss *ast.SelectionSet, fragments map[string]*ast.FragmentDefinition, visiting map[string]bool) int {
	if ss == nil {
		return 0
	}
	max := 0
	for _, sel := range ss.Selections {
		d := 0
		switch s := sel.(type) {
		case *ast.Field:
			d = 1 + selectionSetDepth(s.SelectionSet, fragments, visiting)
		case *ast.InlineFragment:
			d = selectionSetDepth(s.SelectionSet, fragments, visiting)
		case *ast.FragmentSpread:
			name := s.Name.Value
			if visiting[name] { // cyclic fragment - bail rather than recurse forever
				return maxQueryDepth + 1
			}
			if fd, ok := fragments[name]; ok {
				visiting[name] = true
				d = selectionSetDepth(fd.SelectionSet, fragments, visiting)
				delete(visiting, name)
			}
		}
		if d > max {
			max = d
		}
	}
	return max
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
