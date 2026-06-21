package ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/aegisgraph/aegisgraph/pkg/ontology"
)

// Publisher pushes normalized events onto the bus (implemented by broker.Broker).
type Publisher interface {
	Publish(ctx context.Context, ev ontology.Event) error
}

// Server receives scanner output over HTTP and publishes normalized events.
type Server struct {
	pub        Publisher
	collectors map[string]Collector
}

func NewServer(pub Publisher, collectors ...Collector) *Server {
	m := make(map[string]Collector, len(collectors))
	for _, c := range collectors {
		m[c.Source()] = c
	}
	return &Server{pub: pub, collectors: m}
}

// Handler builds the HTTP routes for the ingestion endpoint.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Tool-specific webhook, e.g. POST /ingest/trivy
	mux.HandleFunc("POST /ingest/{source}", s.handleTool)
	// Generic pre-normalized events (one Event or a JSON array of Events).
	mux.HandleFunc("POST /ingest/events", s.handleEvents)
	return mux
}

func (s *Server) handleTool(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	if source == "events" { // handled by the dedicated route
		http.NotFound(w, r)
		return
	}
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
	var nodes, edges int
	for _, ev := range events {
		if err := s.pub.Publish(ctx, ev); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			slog.Error("publish failed", "err", err)
			http.Error(w, "publish failed", http.StatusBadGateway)
			return
		}
		nodes += len(ev.Nodes)
		edges += len(ev.Edges)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted_events": len(events),
		"nodes":           nodes,
		"edges":           edges,
	})
}
