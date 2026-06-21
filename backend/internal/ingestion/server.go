package ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/internal/ratelimit"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

const maxIngestBody = 32 << 20 // 32 MiB

// Publisher pushes normalized events onto the bus (implemented by broker.Broker).
type Publisher interface {
	Publish(ctx context.Context, ev ontology.Event) error
}

// Server receives scanner output over HTTP and publishes normalized events.
type Server struct {
	pub        Publisher
	collectors map[string]Collector
	hmac       *auth.HMACVerifier
	audit      audit.Recorder
	limiter    *ratelimit.Limiter
}

func NewServer(pub Publisher, collectors ...Collector) *Server {
	m := make(map[string]Collector, len(collectors))
	for _, c := range collectors {
		m[c.Source()] = c
	}
	return &Server{pub: pub, collectors: m, audit: audit.Nop{}}
}

// WithRateLimit caps ingest webhook requests per client IP. Returns the server
// for chaining; a nil limiter is a no-op.
func (s *Server) WithRateLimit(l *ratelimit.Limiter) *Server {
	s.limiter = l
	return s
}

// WithHMAC requires an HMAC-SHA256 body signature on every ingest webhook.
// Returns the server for chaining.
func (s *Server) WithHMAC(v *auth.HMACVerifier) *Server {
	s.hmac = v
	return s
}

// WithAudit records verified ingests to the audit log. Returns the server for
// chaining.
func (s *Server) WithAudit(rec audit.Recorder) *Server {
	if rec != nil {
		s.audit = rec
	}
	return s
}

// Handler builds the HTTP routes for the ingestion endpoint. The ingest routes
// (the write path) are HMAC-protected when a verifier is configured; /healthz
// stays open.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Rate limit, then HMAC-verify (when configured), then handle. The limiter
	// runs first so unauthenticated floods are dropped cheaply.
	guard := func(h http.Handler) http.Handler {
		if s.hmac != nil && s.hmac.Enabled() {
			h = s.hmac.Require(s.audit, h)
		}
		return s.limiter.Middleware(h)
	}
	// Tool-specific webhook, e.g. POST /ingest/trivy
	mux.Handle("POST /ingest/{source}", guard(http.HandlerFunc(s.handleTool)))
	// Generic pre-normalized events (one Event or a JSON array of Events).
	mux.Handle("POST /ingest/events", guard(http.HandlerFunc(s.handleEvents)))
	return mux
}

func (s *Server) handleTool(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	c, ok := s.collectors[source]
	if !ok {
		http.Error(w, "unknown collector: "+source, http.StatusNotFound)
		return
	}
	defer r.Body.Close()

	q := r.URL.Query()
	opts := Options{
		Repository: q.Get("repo"),
		RepoSlug:   q.Get("slug"),
		CommitSHA:  q.Get("sha"),
	}
	if n, err := strconv.Atoi(q.Get("pr")); err == nil {
		opts.PRNumber = n
	}
	events, err := c.Parse(http.MaxBytesReader(w, r.Body, 32<<20), opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.publishAll(w, r.Context(), events)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Accept either a single event or an array.
	var events []ontology.Event
	if err := json.Unmarshal(body, &events); err != nil {
		var single ontology.Event
		if err2 := json.Unmarshal(body, &single); err2 != nil {
			http.Error(w, "body must be an Event or array of Events", http.StatusBadRequest)
			return
		}
		events = []ontology.Event{single}
	}
	s.publishAll(w, r.Context(), events)
}

func (s *Server) publishAll(w http.ResponseWriter, ctx context.Context, events []ontology.Event) {
	tenant := auth.PrincipalFromContext(ctx).Tenant
	var nodes, edges int
	for _, ev := range events {
		ev.Tenant = tenant // route to the authenticated tenant's graph
		if err := s.pub.Publish(ctx, ev); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			slog.Error("publish failed", "err", err)
			http.Error(w, "publish failed", http.StatusBadGateway)
			return
		}
		metrics.IngestEvents.WithLabelValues(ev.Source).Inc()
		nodes += len(ev.Nodes)
		edges += len(ev.Edges)
	}
	metrics.IngestNodes.Add(float64(nodes))
	metrics.IngestEdges.Add(float64(edges))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted_events": len(events),
		"nodes":           nodes,
		"edges":           edges,
	})
}
