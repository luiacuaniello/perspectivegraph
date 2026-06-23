// Command perspectivegraph runs the full PerspectiveGraph backend: ingestion webhook,
// normalization consumer, attack-path analyzer, and GraphQL API. Each layer
// runs concurrently and is wired together through the NATS event bus.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/action"
	"github.com/luiacuaniello/perspectivegraph/internal/ai"
	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/api"
	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/broker"
	"github.com/luiacuaniello/perspectivegraph/internal/config"
	"github.com/luiacuaniello/perspectivegraph/internal/connector"
	awsconn "github.com/luiacuaniello/perspectivegraph/internal/connector/aws"
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
	"github.com/luiacuaniello/perspectivegraph/internal/exportsign"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/age"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/build"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/cloudnet"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/custodian"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/dataclass"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/falco"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/k8s"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/semgrep"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/sso"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/supplychain"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/trivy"
	"github.com/luiacuaniello/perspectivegraph/internal/leader"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
	"github.com/luiacuaniello/perspectivegraph/internal/notify"
	"github.com/luiacuaniello/perspectivegraph/internal/policy"
	"github.com/luiacuaniello/perspectivegraph/internal/ratelimit"
	"github.com/luiacuaniello/perspectivegraph/internal/search"
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
	"github.com/luiacuaniello/perspectivegraph/internal/threatintel"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

func main() {
	// Operator utility: verify the audit log's hash chain and exit.
	if len(os.Args) >= 3 && os.Args[1] == "verify-audit" {
		sealer, err := cryptostore.New(os.Getenv("STORE_ENCRYPTION_KEY"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify-audit:", err)
			os.Exit(1)
		}
		n, err := audit.Verify(os.Args[2], audit.WithSealer(sealer))
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit chain INVALID after %d records: %v\n", n, err)
			os.Exit(1)
		}
		fmt.Printf("audit chain OK: %d records verified\n", n)
		return
	}

	// Scale/load utility: generate a large synthetic attack surface and POST it to
	// the ingest webhook, so the analyzer's scaling can be exercised end-to-end on a
	// running stack. See runGenload for flags. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "genload" {
		if err := runGenload(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "genload:", err)
			os.Exit(1)
		}
		return
	}

	// Container healthcheck: hit the API's /healthz and exit 0/1. Lets the
	// distroless image (no shell, no curl) be probed with `perspectivegraph
	// healthz` from a Docker HEALTHCHECK / compose healthcheck.
	if len(os.Args) >= 2 && os.Args[1] == "healthz" {
		if err := healthCheck(); err != nil {
			fmt.Fprintln(os.Stderr, "healthz:", err)
			os.Exit(1)
		}
		return
	}

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
	// One isolated store (Apache AGE graph, or in-memory) per tenant, created
	// lazily by the manager. The default tenant is created eagerly.
	factory, backend, err := storeFactory(ctx, cfg)
	if err != nil {
		return err
	}
	manager, err := graph.NewManager(ctx, factory)
	if err != nil {
		return err
	}
	defer manager.Close()

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
	intel := threatintel.New(cfg.ThreatIntelEnabled, cfg.KEVFeedURL, cfg.EPSSAPIURL)
	if intel.Enabled() {
		slog.Info("threat intel: KEV + EPSS enrichment enabled")
	}
	normalizer := normalization.New(manager).WithIndexer(indexer).WithThreatIntel(intel).WithScrub(cfg.ScrubIngest)
	sinks := action.MultiSink{
		action.ConsoleSink{},
		action.NewGitHubCommenter(action.GitHubConfig{
			Token:   cfg.GitHubToken,
			BaseURL: cfg.GitHubAPIURL,
			DryRun:  cfg.GitHubDryRun,
		}),
		action.NewGitHubChecker(action.GitHubConfig{
			Token:   cfg.GitHubToken,
			BaseURL: cfg.GitHubAPIURL,
			DryRun:  cfg.GitHubDryRun,
		}, cfg.DashboardURL),
		action.NewGitLabCommenter(action.GitLabConfig{
			Token:   cfg.GitLabToken,
			BaseURL: cfg.GitLabAPIURL,
			DryRun:  cfg.GitLabDryRun,
		}),
	}
	notifier := notify.New(cfg.AlertWebhookURL, cfg.AlertWebhookFormat)
	if notifier.Enabled() {
		slog.Info("drift alerting: webhook enabled", "format", cfg.AlertWebhookFormat)
	}

	// Leader election gates at-most-once external actions (drift alerts, PR
	// comments) so multiple replicas don't duplicate them. With Apache AGE we use
	// a Postgres advisory lock; in-memory (single process) is always the leader.
	var elector analyzer.Leader = leader.AlwaysLeader{}
	if backend == "apache-age" {
		if pgLeader, err := leader.NewPostgres(cfg.PostgresDSN, "analyzer"); err != nil {
			slog.Warn("leader election unavailable, defaulting to always-leader", "err", err)
		} else {
			defer pgLeader.Close()
			elector = pgLeader
		}
	}

	// At-rest encryption for the file-backed governance stores + audit log. The
	// tool's persisted state is a map of how to attack the org plus who viewed it,
	// so a stolen volume/backup shouldn't surrender it in plaintext. Empty key →
	// Nop (plaintext), with a warning.
	sealer, err := cryptostore.New(cfg.StoreEncryptionKey)
	if err != nil {
		return fmt.Errorf("store encryption: %w", err)
	}
	if sealer.Enabled() {
		slog.Info("at-rest encryption: governance stores + audit log are AES-256-GCM encrypted")
	}

	// Ed25519 export signing: OSCAL/SIEM exports leave the trust boundary, so a
	// consumer should be able to verify integrity + origin. Empty key → unsigned.
	exportSigner, err := exportsign.New(cfg.ExportSigningKey)
	if err != nil {
		return fmt.Errorf("export signing: %w", err)
	}
	if exportSigner.Enabled() {
		slog.Info("export signing: OSCAL/SIEM exports are Ed25519-signed", "pubkey_at", "GET /export/pubkey")
	}

	// ── Temporal history (optional file backing) ─────────────────────
	// One store, shared: the analyzer writes each pass, the API reads it.
	historyStore, err := history.New(cfg.HistoryPath, history.WithSealer(sealer))
	if err != nil {
		return fmt.Errorf("history store: %w", err)
	}
	if historyStore.Persistent() {
		slog.Info("history store: file-backed", "path", cfg.HistoryPath)
	} else {
		slog.Warn("history store: in-memory only — path age / MTTR / trend reset on restart (set HISTORY_PATH to persist)")
	}

	analyzerSvc := analyzer.NewService(manager, cfg.AnalyzerInterval, sinks).
		WithPolicy(policy.NewEngine(policy.Builtins()...)).
		WithNotifier(notifier).
		WithLeader(elector).
		WithMaxHops(cfg.AnalyzerMaxHops).
		WithDBPaths(cfg.AnalyzerDBPaths).
		WithWorkers(cfg.AnalyzerWorkers).
		WithIncremental(cfg.AnalyzerIncremental).
		WithTTL(cfg.GraphTTL).
		WithHistory(historyStore)
	if cfg.GraphTTL > 0 {
		slog.Info("staleness pruning enabled — assets not re-observed within the TTL are removed (leader only)", "ttl", cfg.GraphTTL)
	}
	if cfg.AnalyzerIncremental {
		slog.Info("incremental analysis enabled — patching a resident snapshot with per-pass deltas instead of re-reading the whole graph")
	}
	if cfg.AnalyzerWorkers > 0 {
		slog.Info("analyzer pathfinding parallelism pinned", "workers", cfg.AnalyzerWorkers)
	}

	// ── Agentless connectors (optional; PULL from external systems) ──
	// Leader-only, so replicas don't multiply API calls. Feeds the same bus as the
	// push webhooks, so the whole downstream pipeline is reused.
	connSched := buildConnectors(ctx, cfg, bus, elector)
	if connSched.Enabled() {
		slog.Info("agentless connectors enabled", "interval", cfg.ConnectorInterval)
	}

	// ── Audit (optional; tamper-evident hash-chained log) ────────────
	var auditRec audit.Recorder = audit.Nop{}
	if cfg.AuditLogPath != "" {
		alog, err := audit.Open(cfg.AuditLogPath, audit.WithSealer(sealer))
		if err != nil {
			return err
		}
		defer alog.Close()
		auditRec = alog
		slog.Info("audit log enabled", "path", cfg.AuditLogPath)
	}

	// ── Abuse watchers: exfiltration of the attack map + auth brute force ──
	// A 0 threshold disables. Alerts are logged (WARN) and written to the audit
	// log — ship those to your SIEM for paging.
	const watchWindow, watchCooldown = 5 * time.Minute, 15 * time.Minute
	exfilWatcher := secwatch.New(cfg.ExfilAlertThreshold, watchWindow, watchCooldown, func(key string, count int) {
		slog.Warn("ALERT: possible attack-map exfiltration", "principal", key, "paths_in_window", count)
		auditRec.Record("exfil.alert", "secwatch", "", "", map[string]any{"principal": key, "count": count})
	})
	if exfilWatcher.Enabled() {
		slog.Info("exfiltration alerting enabled", "threshold_paths_per_5m", cfg.ExfilAlertThreshold)
	}
	authGuard := secwatch.New(cfg.AuthLockoutThreshold, watchWindow, watchCooldown, func(key string, count int) {
		slog.Warn("ALERT: auth brute-force lockout", "remote", key, "failures_in_window", count)
		auditRec.Record("auth.lockout.alert", "secwatch", "", "", map[string]any{"remote": key, "count": count})
	})
	if authGuard.Enabled() {
		slog.Info("auth brute-force lockout enabled", "threshold_failures_per_5m", cfg.AuthLockoutThreshold)
	}

	// ── Auth (optional; open with a loud warning when unset) ─────────
	hmac := auth.NewHMACVerifier(hmacSecrets(cfg), 32<<20)
	if hmac.Enabled() {
		slog.Info("ingest auth: per-tenant HMAC signature required")
	} else {
		slog.Warn("ingest auth DISABLED — webhook endpoints are open (set INGEST_HMAC_SECRET)")
	}
	// Fail-closed: if OIDC is enabled, refuse to start without both iss and aud.
	// A JWT verifier that skips issuer/audience accepts any RS256 token the IdP
	// (or another relying party sharing it) ever minted — a silent auth weakness.
	if cfg.OIDCJWKSURL != "" && (cfg.OIDCIssuer == "" || cfg.OIDCAudience == "") {
		return errors.New("OIDC enabled (OIDC_JWKS_URL set) but OIDC_ISSUER and/or OIDC_AUDIENCE is empty: " +
			"refusing to start without iss/aud validation. Set both, or unset OIDC_JWKS_URL to use static API_TOKENS")
	}
	authn := auth.Chain{
		auth.NewTokenStore(cfg.APITokens),
		auth.NewJWTAuthenticator(auth.JWTConfig{
			JWKSURL:  cfg.OIDCJWKSURL,
			Issuer:   cfg.OIDCIssuer,
			Audience: cfg.OIDCAudience,
		}),
	}
	if authn.Enabled() {
		slog.Info("API auth: bearer credential required (GraphiQL disabled)")
	} else {
		slog.Warn("API auth DISABLED — GraphQL endpoint is open (set API_TOKENS or OIDC_JWKS_URL)")
	}

	// Per-IP rate limiters (0 disables). burst = 2×rps + 1 absorbs short bursts
	// (a `make seed` fires several POSTs back-to-back) without throttling.
	ingestLimiter := ratelimit.New(cfg.IngestRateRPS, int(cfg.IngestRateRPS*2)+1)
	apiLimiter := ratelimit.New(cfg.APIRateRPS, int(cfg.APIRateRPS*2)+1)
	if ingestLimiter.Enabled() || apiLimiter.Enabled() {
		slog.Info("rate limiting enabled", "ingest_rps", cfg.IngestRateRPS, "api_rps", cfg.APIRateRPS)
	}

	// ── Triage/suppression store (optional file backing) ─────────────
	suppressStore, err := suppress.New(cfg.SuppressionsPath, suppress.WithSealer(sealer))
	if err != nil {
		return fmt.Errorf("suppression store: %w", err)
	}
	if suppressStore.Persistent() {
		slog.Info("suppression store: file-backed", "path", cfg.SuppressionsPath)
	} else {
		slog.Warn("suppression store: in-memory only — triage decisions are lost on restart (set SUPPRESSIONS_PATH to persist)")
	}

	// ── Remediation ticketing (optional file backing + webhook) ──────
	ticketStore, err := ticket.New(cfg.TicketsPath, cfg.TicketWebhookURL, ticket.WithSealer(sealer))
	if err != nil {
		return fmt.Errorf("ticket store: %w", err)
	}
	if ticketStore.Dispatches() {
		slog.Info("ticketing: dispatching new tickets to external tracker", "webhook", cfg.TicketWebhookURL)
	} else {
		slog.Warn("ticketing: dry-run — tickets are tracked locally only (set TICKET_WEBHOOK_URL to dispatch)")
	}

	// ── Red-team / BAS validation store (optional file backing) ──────
	validationStore, err := validation.New(cfg.ValidationsPath, validation.WithSealer(sealer))
	if err != nil {
		return fmt.Errorf("validation store: %w", err)
	}
	if !validationStore.Persistent() {
		slog.Warn("validation store: in-memory only — red-team/BAS verdicts reset on restart (set VALIDATIONS_PATH to persist)")
	}

	ingestSrv := ingestion.NewServer(bus,
		trivy.New(), semgrep.New(), custodian.New(), falco.New(), build.New(), k8s.New(), cloudnet.New(), iam.New(), supplychain.New(), sso.New(), dataclass.New()).
		WithHMAC(hmac).WithAudit(auditRec).WithRateLimit(ingestLimiter).
		WithConnectorStatus(func() any { return connSched.Status() })
	prOpener := action.NewGitHubPROpener(action.GitHubConfig{Token: cfg.GitHubToken, BaseURL: cfg.GitHubAPIURL, DryRun: cfg.GitHubDryRun})
	aiCfg := ai.Config{
		APIKey: cfg.AnthropicAPIKey, Model: cfg.AnthropicModel, BaseURL: cfg.AnthropicBaseURL, MaxTokens: cfg.AIMaxTokens,
		HFToken: cfg.HFToken, HFModel: cfg.HFModel, HFBaseURL: cfg.HFBaseURL,
	}
	aiClient := ai.New(aiCfg)
	if aiClient.Enabled() {
		provider, model := ai.Provider(aiCfg)
		slog.Info("AI-native layer enabled", "provider", provider, "model", model)
	}
	apiHandler, err := buildAPI(manager, analyzerSvc, indexer, authn, auditRec, apiLimiter, suppressStore, historyStore, ticketStore, validationStore, cfg.CORSAllowedOrigins, exportSigner, exfilWatcher, authGuard, authInfoFromConfig(cfg, authn.Enabled()), prOpener, aiClient)
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

	// Agentless connector poll loop (no-op when none enabled).
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := connSched.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("connector scheduler stopped", "err", err)
		}
	}()

	// HTTP servers. Explicit timeouts blunt slow-client / Slowloris resource
	// exhaustion (Go's http.Server has none by default). ReadHeaderTimeout is the
	// key Slowloris defense; ReadTimeout is generous enough for a 32 MiB scanner
	// upload on ingest, WriteTimeout for a large SIEM/OSCAL export on the API.
	ingestHTTP := &http.Server{
		Addr:              cfg.IngestAddr,
		Handler:           ingestSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	apiHTTP := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           apiHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	serveHTTP(ctx, &wg, "ingestion", ingestHTTP)
	serveHTTP(ctx, &wg, "api", apiHTTP)

	slog.Info("perspectivegraph running",
		"api", cfg.APIAddr, "ingest", cfg.IngestAddr, "graph", backend)

	<-ctx.Done()
	slog.Info("signal received, draining…")
	wg.Wait()
	return nil
}

// buildConnectors assembles the enabled agentless connectors into a leader-gated
// scheduler. Unknown names are skipped with a warning, and a connector that fails
// to initialize is skipped (not fatal) so one misconfigured source can't block
// boot. The scheduler is a no-op when nothing is enabled.
func buildConnectors(ctx context.Context, cfg config.Config, pub connector.Publisher, elector connector.Leader) *connector.Scheduler {
	var conns []connector.Connector
	for _, name := range cfg.ConnectorsEnabled {
		switch name {
		case "aws":
			c, err := awsconn.NewFromConfig(ctx, awsconn.Config{
				Mode:        cfg.AWSConnectorMode,
				FixturesDir: cfg.AWSFixturesDir,
				Region:      cfg.AWSRegion,
				RoleARN:     cfg.AWSRoleARN,
			})
			if err != nil {
				slog.Error("aws connector disabled", "err", err)
				continue
			}
			slog.Info("aws connector enabled", "mode", c.Mode())
			conns = append(conns, c)
		default:
			slog.Warn("unknown connector, skipping", "name", name)
		}
	}
	return connector.NewScheduler(pub, cfg.ConnectorInterval, conns...).
		WithLeader(elector).
		WithTenant(cfg.ConnectorTenant).
		WithTimeout(cfg.ConnectorTimeout)
}

// storeFactory probes Apache AGE once and returns a per-tenant store factory.
// Each tenant gets its own AGE graph (the default tenant keeps the configured
// graph name so existing data is preserved). On probe failure it falls back to
// in-memory stores for zero-dependency local dev — UNLESS GRAPH_STRICT is set,
// in which case it returns an error and the process refuses to start rather than
// silently dropping persistence (data that "works" in the demo but is lost on
// restart is its own kind of incident).
func storeFactory(ctx context.Context, cfg config.Config) (graph.StoreFactory, string, error) {
	graphName := func(tenant string) string {
		if tenant == graph.DefaultTenant {
			return cfg.AGEGraph
		}
		return cfg.AGEGraph + "_" + tenant
	}

	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s, err := age.OpenOrCreate(probeCtx, cfg.PostgresDSN, cfg.AGEGraph)
	if err == nil {
		_ = s.Close()
		slog.Info("graph core: Apache AGE (per-tenant graphs)", "default_graph", cfg.AGEGraph)
		return func(ctx context.Context, tenant string) (graph.Store, error) {
			return age.OpenOrCreate(ctx, cfg.PostgresDSN, graphName(tenant))
		}, "apache-age", nil
	}

	if cfg.GraphStrict {
		return nil, "", fmt.Errorf("GRAPH_STRICT is set but Apache AGE is unavailable: %w", err)
	}
	slog.Warn("Apache AGE UNAVAILABLE — falling back to IN-MEMORY stores (data is NOT persisted; set GRAPH_STRICT=true to fail instead)", "err", err)
	return func(context.Context, string) (graph.Store, error) {
		return memory.New(), nil
	}, "memory", nil
}

// hmacSecrets builds the tenant→secret map from the single-secret (default
// tenant) and the per-tenant spec.
func hmacSecrets(cfg config.Config) map[string]string {
	secrets := map[string]string{}
	if cfg.IngestHMACSecret != "" {
		secrets[graph.DefaultTenant] = cfg.IngestHMACSecret
	}
	for _, entry := range strings.Split(cfg.IngestHMACSecrets, ",") {
		if tenant, secret, ok := strings.Cut(strings.TrimSpace(entry), ":"); ok && tenant != "" && secret != "" {
			secrets[graph.NormalizeTenant(tenant)] = secret
		}
	}
	return secrets
}

// authInfoFromConfig builds the public auth config the dashboard's login gate
// reads (GET /auth/config). It carries no secrets — only whether a credential is
// required and the IdP's public coordinates for an SSO redirect.
func authInfoFromConfig(cfg config.Config, authEnabled bool) api.AuthInfo {
	info := api.AuthInfo{Required: authEnabled, Mode: "none"}
	if !authEnabled {
		return info
	}
	hasTokens := len(cfg.APITokens) > 0
	hasOIDC := cfg.OIDCJWKSURL != ""
	switch {
	case hasOIDC && hasTokens:
		info.Mode = "both"
	case hasOIDC:
		info.Mode = "oidc"
	default:
		info.Mode = "token"
	}
	if hasOIDC {
		info.OIDC = &api.OIDCInfo{
			Issuer:       cfg.OIDCIssuer,
			Audience:     cfg.OIDCAudience,
			ClientID:     cfg.OIDCClientID,
			AuthorizeURL: cfg.OIDCAuthURL,
			TokenURL:     cfg.OIDCTokenURL,
			Scopes:       cfg.OIDCScopes,
		}
	}
	return info
}

func buildAPI(manager *graph.Manager, svc *analyzer.Service, idx search.Indexer, authn auth.Authenticator, rec audit.Recorder, limiter *ratelimit.Limiter, suppressStore *suppress.Store, historyStore *history.Store, ticketStore *ticket.Store, validationStore *validation.Store, corsOrigins []string, exportSigner *exportsign.Signer, exfilWatcher, authGuard *secwatch.Watcher, authInfo api.AuthInfo, prOpener action.PROpener, aiClient ai.Client) (http.Handler, error) {
	return api.New(manager, svc, idx).WithAuth(authn, rec).WithRateLimit(limiter).WithSuppress(suppressStore).WithHistory(historyStore).WithTickets(ticketStore).WithValidation(validationStore).WithCORSOrigins(corsOrigins).WithExportSigner(exportSigner).WithAbuseWatchers(exfilWatcher, authGuard).WithAuthInfo(authInfo).WithRemediationPR(prOpener).WithAI(aiClient).Handler()
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
	go func() { // #nosec G118 -- server-lifecycle goroutine; graceful-shutdown uses a fresh Background context by design (the request scope is already gone)
		defer wg.Done()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
}

// healthCheck performs a one-shot GET against the local API /healthz, used by
// the container healthcheck. It targets the configured API_ADDR, rewriting a
// wildcard/empty host to loopback so it works from inside the container.
func healthCheck() error {
	addr := os.Getenv("API_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid API_ADDR %q: %w", addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + "/healthz"

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url) // #nosec G704 -- url is the operator-configured local healthz address (self-check), not user input
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
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
