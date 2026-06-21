// Command aegisgraph runs the full AegisGraph backend: ingestion webhook,
// normalization consumer, attack-path analyzer, and GraphQL API. Each layer
// runs concurrently and is wired together through the NATS event bus.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/aegisgraph/aegisgraph/internal/action"
	"github.com/aegisgraph/aegisgraph/internal/analyzer"
	"github.com/aegisgraph/aegisgraph/internal/api"
	"github.com/aegisgraph/aegisgraph/internal/broker"
	"github.com/aegisgraph/aegisgraph/internal/config"
	"github.com/aegisgraph/aegisgraph/internal/graph"
	"github.com/aegisgraph/aegisgraph/internal/graph/age"
	"github.com/aegisgraph/aegisgraph/internal/graph/memory"
	"github.com/aegisgraph/aegisgraph/internal/ingestion"
	"github.com/aegisgraph/aegisgraph/internal/ingestion/custodian"
	"github.com/aegisgraph/aegisgraph/internal/ingestion/falco"
	"github.com/aegisgraph/aegisgraph/internal/ingestion/semgrep"
	"github.com/aegisgraph/aegisgraph/internal/ingestion/trivy"
	"github.com/aegisgraph/aegisgraph/internal/normalization"
	"github.com/aegisgraph/aegisgraph/internal/policy"
	"github.com/aegisgraph/aegisgraph/internal/search"
)

func main() {
	cfg := config.Load()
	setupLogging(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
	slog.Info("shutdown complete")
}

func run(ctx context.Context, cfg config.Config) error {
	// ── Graph core ──────────────────────────────────────────────────
	store := openStore(ctx, cfg)
	defer store.Close()

	// ── Event bus ───────────────────────────────────────────────────
	bus, err := broker.Connect(ctx, cfg.NATSURL, cfg.NATSStream, cfg.NATSSubject)
	if err != nil {
		return err
	}
	defer bus.Close()

	// ── Layers ──────────────────────────────────────────────────────
	indexer := search.New(cfg.OpenSearchURL)
	if indexer.Enabled() {
		slog.Info("full-text index: OpenSearch", "url", cfg.OpenSearchURL)
	}
	normalizer := normalization.New(store).WithIndexer(indexer)
	sinks := action.MultiSink{
		action.ConsoleSink{},
		action.NewGitHubCommenter(action.GitHubConfig{
			Token:   cfg.GitHubToken,
			BaseURL: cfg.GitHubAPIURL,
			DryRun:  cfg.GitHubDryRun,
		}),
		action.NewGitLabCommenter(action.GitLabConfig{
			Token:   cfg.GitLabToken,
			BaseURL: cfg.GitLabAPIURL,
			DryRun:  cfg.GitLabDryRun,
		}),
	}
	analyzerSvc := analyzer.NewService(store, cfg.AnalyzerInterval, sinks).
		WithPolicy(policy.NewEngine(policy.Builtins()...))
	ingestSrv := ingestion.NewServer(bus, trivy.New(), semgrep.New(), custodian.New(), falco.New())
	apiHandler, err := buildAPI(store, analyzerSvc, indexer)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup

	// Normalization consumer: bus -> identity resolution -> graph.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := bus.Consume(ctx, "normalizer", normalizer.Handle); err != nil &&
			!errors.Is(err, context.Canceled) {
			slog.Error("normalizer stopped", "err", err)
		}
	}()

	// Attack-path analyzer loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := analyzerSvc.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("analyzer stopped", "err", err)
		}
	}()

	// HTTP servers.
	ingestHTTP := &http.Server{Addr: cfg.IngestAddr, Handler: ingestSrv.Handler()}
	apiHTTP := &http.Server{Addr: cfg.APIAddr, Handler: apiHandler}
	serveHTTP(ctx, &wg, "ingestion", ingestHTTP)
	serveHTTP(ctx, &wg, "api", apiHTTP)

	slog.Info("aegisgraph running",
		"api", cfg.APIAddr, "ingest", cfg.IngestAddr, "graph", graphBackendName(store))

	<-ctx.Done()
	slog.Info("signal received, draining…")
	wg.Wait()
	return nil
}

// openStore prefers the Apache AGE graph core, falling back to the in-memory
// store (with a warning) when Postgres is unreachable — handy for local dev.
func openStore(ctx context.Context, cfg config.Config) graph.Store {
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if s, err := age.Open(pingCtx, cfg.PostgresDSN, cfg.AGEGraph); err == nil {
		slog.Info("graph core: Apache AGE", "graph", cfg.AGEGraph)
		return s
	} else {
		slog.Warn("Apache AGE unavailable, using in-memory store", "err", err)
	}
	return memory.New()
}

func buildAPI(store graph.Store, svc *analyzer.Service, idx search.Indexer) (http.Handler, error) {
	return api.New(store, svc, idx).Handler()
}

func serveHTTP(ctx context.Context, wg *sync.WaitGroup, name string, srv *http.Server) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server failed", "name", name, "err", err)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
}

func graphBackendName(s graph.Store) string {
	switch s.(type) {
	case *memory.Store:
		return "memory"
	case *age.Store:
		return "apache-age"
	default:
		return "unknown"
	}
}

func setupLogging(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}
