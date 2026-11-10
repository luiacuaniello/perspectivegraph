// Command perspectivegraph runs the full PerspectiveGraph backend: ingestion webhook,
// normalization consumer, attack-path analyzer, and GraphQL API. Each layer
// runs concurrently and is wired together through the NATS event bus.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
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
	"github.com/luiacuaniello/perspectivegraph/internal/clientip"
	"github.com/luiacuaniello/perspectivegraph/internal/config"
	"github.com/luiacuaniello/perspectivegraph/internal/connector"
	awsconn "github.com/luiacuaniello/perspectivegraph/internal/connector/aws"
	azureconn "github.com/luiacuaniello/perspectivegraph/internal/connector/azure"
	k8sconn "github.com/luiacuaniello/perspectivegraph/internal/connector/kubernetes"
	"github.com/luiacuaniello/perspectivegraph/internal/coverage"
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
	"github.com/luiacuaniello/perspectivegraph/internal/exportsign"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/age"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/kevholdout"
	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
	"github.com/luiacuaniello/perspectivegraph/internal/notify"
	"github.com/luiacuaniello/perspectivegraph/internal/ratelimit"
	"github.com/luiacuaniello/perspectivegraph/internal/reqid"
	"github.com/luiacuaniello/perspectivegraph/internal/search"
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
	"github.com/luiacuaniello/perspectivegraph/internal/threatintel"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

func main() {
	// What someone types first at a binary they have just downloaded. `help <command>` is
	// that command's -h, so it is rewritten into one and dispatched below with the rest.
	if len(os.Args) >= 2 && (os.Args[1] == "help" || helpFlag(os.Args[1])) {
		if os.Args[1] != "help" || len(os.Args) == 2 || os.Args[2] == "help" || os.Args[2] == "version" {
			printUsage(os.Stdout)
			return
		}
		os.Args = []string{os.Args[0], os.Args[2], "-h"}
	}
	if len(os.Args) >= 2 && (os.Args[1] == "version" || versionFlag(os.Args[1])) {
		fmt.Println(versionLine())
		return
	}

	// Operator utility: verify the audit log's hash chain and exit. Dispatching on the
	// subcommand alone - not on it plus an argument - is deliberate: `verify-audit` with
	// nothing after it used to fall through every other case and START THE SERVER, so a
	// typo in a verification step became a running process nobody meant to launch.
	if len(os.Args) >= 2 && os.Args[1] == "verify-audit" {
		if err := runVerifyAudit(os.Args[2:], os.Stdout); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return
			}
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	// Scale/load utility: generate a large synthetic attack surface and POST it to
	// the ingest webhook, so the analyzer's scaling can be exercised end-to-end on a
	// running stack. See runGenload for flags. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "genload" {
		if err := runGenload(os.Args[2:]); err != nil {
			fail("genload", err)
		}
		return
	}

	// Calibration self-test: post synthetic verdicts drawn from a known reality (a
	// scenario), so the calibration math + diagnostics can be exercised and tested in
	// development without real vulnerable infra. See runGenverdicts. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "genverdicts" {
		if err := runGenverdicts(os.Args[2:]); err != nil {
			fail("genverdicts", err)
		}
		return
	}

	// Merge gate: ingest one scanner report stamped with a pull request's identity, wait
	// for the engine to place it in the estate graph, and exit non-zero when the change
	// puts a sensitive asset within reach. Blocks on attack paths, not on CVE counts. Its
	// exit code is its interface, so it exits itself rather than returning. See runGate.
	if len(os.Args) >= 2 && os.Args[1] == "gate" {
		// staticcheck is right that this can only be true: runGate reaches every verdict
		// through reportAndExit, which exits, so the `return nil` below it is unreachable
		// and the only returns left are failures. The check stays anyway - it is what
		// makes a future path that DOES return nil fail closed instead of exiting 0 on a
		// verdict nobody produced, which on a merge gate is the whole ballgame.
		//lint:ignore SA4023 deliberate: a gate must fail closed if it ever returns.
		if err := runGate(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "gate:", err)
			os.Exit(gateExitError)
		}
		return
	}

	// BAS → /validations bridge: map a tool-agnostic attack report onto the engine's
	// live attack paths and record the verdicts, so a real red-team/BAS run feeds the
	// calibration loop with no custom integration. See runImportVerdicts. Exits done.
	if len(os.Args) >= 2 && os.Args[1] == "importverdicts" {
		if err := runImportVerdicts(os.Args[2:]); err != nil {
			fail("importverdicts", err)
		}
		return
	}

	// Zero-cost real ingest: Trivy-scan a genuinely vulnerable image and wire the
	// minimal topology so the real CVE sits on an internet → crown-jewel path - the
	// on-ramp to calibrating on real data. See runIngestReal. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "ingestreal" {
		if err := runIngestReal(os.Args[2:]); err != nil {
			fail("ingestreal", err)
		}
		return
	}

	// #6 decision tool: does the environment have AND-semantics (a compromise needing
	// several prerequisites at once) or pure OR-reachability? Scans the live graph and
	// counts the AND candidates on critical paths. See runAndProbe. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "andprobe" {
		if err := runAndProbe(os.Args[2:]); err != nil {
			fail("andprobe", err)
		}
		return
	}

	// Send one scanner report to a running engine, signed the way its ingestion endpoint
	// requires - what a CI job or a cron job calls instead of curl and openssl. See
	// runIngest. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "ingest" {
		if err := runIngest(os.Args[2:], os.Stdin, os.Stdout); err != nil {
			fail("ingest", err)
		}
		return
	}

	// Real-account validation primitive: run the live AWS connector (sdk transport)
	// once and show the discovered internet-exposed seeds vs the SG-open instances the
	// route/NACL layer suppressed - the read-only "does it read my real VPC correctly?"
	// check. See runAwsCollect. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "awscollect" {
		if err := runAwsCollect(os.Args[2:]); err != nil {
			fail("awscollect", err)
		}
		return
	}

	// Red-team oracle: ask AWS's own policy evaluator whether the privilege-escalation
	// claims are real, applying the SCPs, boundaries and conditions the engine skips.
	// Read-only dry runs; creates nothing. See runRedteam. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "redteam" {
		if err := runRedteam(os.Args[2:]); err != nil {
			fail("redteam", err)
		}
		return
	}

	// MCP server: expose the engine as tools an AI agent can call (stdio JSON-RPC).
	// stdout is the protocol channel, so this must return before any logging starts.
	if len(os.Args) >= 2 && os.Args[1] == "mcp" {
		if err := runMCP(os.Args[2:]); err != nil {
			fail("mcp", err)
		}
		return
	}

	// Container healthcheck: hit the API's /healthz and exit 0/1. Lets the
	// distroless image (no shell, no curl) be probed with `perspectivegraph
	// healthz` from a Docker HEALTHCHECK / compose healthcheck.
	if len(os.Args) >= 2 && os.Args[1] == "healthz" {
		if len(os.Args) > 2 && helpFlag(os.Args[2]) {
			// It takes no flags, and probing a server because someone asked what it does
			// would answer a different question.
			fmt.Println("usage: perspectivegraph healthz - GET /healthz on API_ADDR (over TLS when TLS_CERT_FILE and TLS_KEY_FILE are set); exit 0 on a 200, 1 otherwise")
			return
		}
		if err := healthCheck(); err != nil {
			fmt.Fprintln(os.Stderr, "healthz:", err)
			os.Exit(1)
		}
		return
	}

	// Everything past this point starts the server, so an argument that reached here is a
	// subcommand nobody recognised - and silently starting a server instead is a nasty way
	// to fail. In CI it does not look like an error at all: the process binds a port and
	// sits there until the job's own timeout kills it, hours later, with no verdict and no
	// clue why. A typo, or a `gate` invocation against a release too old to have it, should
	// say so in one line.
	if len(os.Args) >= 2 {
		fmt.Fprintf(os.Stderr, "perspectivegraph: unknown subcommand %q\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "subcommands:", strings.Join(subcommands, ", "))
		fmt.Fprintln(os.Stderr, "run with no arguments to start the server; configuration comes from the environment")
		os.Exit(gateExitError)
	}

	cfg := config.Load()
	setupLogging(cfg.LogLevel, cfg.LogFormat)
	// The first line of every log, and a series on /metrics: which release this is. A
	// report of a problem either names its version or cannot be answered, and the image
	// tag is not always in front of whoever is reading the logs.
	slog.Info("perspectivegraph starting", "version", buildVersion(), "go", runtime.Version())
	metrics.BuildInfo.WithLabelValues(buildVersion(), runtime.Version()).Set(1)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
	slog.Info("shutdown complete")
}

// isProduction reports whether the operator has declared a production deployment.
// The comparison is deliberately narrow: only the exact string "production" (any
// case, trimmed) opts in. An empty, misspelled or unknown value keeps the permissive
// demo behaviour, so a typo can never silently *enable* a stricter mode the operator
// did not ask for - and, more importantly, this flag can only ever add checks, never
// remove them.
func isProduction(env string) bool {
	return strings.EqualFold(strings.TrimSpace(env), "production")
}

// checkProductionConfig enforces the fail-closed rules for a declared production
// deployment. It is pure configuration validation, deliberately run before the
// process connects to anything: a misconfiguration should fail on its own terms,
// not hide behind whichever dependency happens to be unreachable first.
//
// The demo profile stays permissive on purpose - that is what makes `make demo` one
// command - which means the insecure mode is the one you get by doing nothing.
// Declaring the environment turns that into a refusal to start, so the failure is a
// startup error someone reads rather than a warning scrolling past in a log.
func checkProductionConfig(cfg config.Config) error {
	if !isProduction(cfg.Env) {
		return nil
	}
	// The GraphQL endpoint serves the organisation's own attack map - the shortest
	// route from the internet to everything worth stealing - so an open one is a
	// briefing document for whoever finds it.
	if cfg.APITokens == "" && cfg.OIDCJWKSURL == "" {
		return errors.New("PG_ENV=production but no API credential is configured: refusing to start with an open " +
			"GraphQL endpoint, which would publish this environment's attack paths to anyone who can reach it. " +
			"Set API_TOKENS (static bearer tokens) or OIDC_JWKS_URL + OIDC_ISSUER + OIDC_AUDIENCE (SSO)")
	}
	// A non-empty API_TOKENS that parses to nothing is worse than an empty one, because
	// it satisfies the check above and still leaves the endpoint open. Every malformed
	// entry is dropped with a warning that scrolls past in a startup log, and what is
	// left is auth DISABLED on a deployment its operator declared production - the exact
	// outcome this gate exists to prevent, reached by a missing ":admin".
	if cfg.OIDCJWKSURL == "" && auth.NewTokenStore(cfg.APITokens).Len() == 0 {
		return errors.New("PG_ENV=production but API_TOKENS yields no usable credential: every entry was " +
			"dropped as malformed, as naming an unknown role, or as already expired, which would leave the " +
			"GraphQL endpoint open. Each entry is token:role[:tenant[:YYYY-MM-DD]] and role is viewer or admin, " +
			"e.g. API_TOKENS=s3cr3t:admin. Check the startup warnings for which entry was rejected")
	}
	// A passphrase becomes the store key through a single SHA-256, so whoever holds an
	// encrypted backup can test guesses at hashing speed. Converting keeps every store
	// readable, because the SHA-256 of the passphrase IS the key it was encrypting with.
	if cryptostore.IsPassphrase(cfg.StoreEncryptionKey) {
		return errors.New("PG_ENV=production but STORE_ENCRYPTION_KEY is a passphrase, which becomes the key " +
			"through a single SHA-256 - whoever holds an encrypted backup can test guesses at hashing speed. Set " +
			"a random key of 64 hex characters (openssl rand -hex 32). To keep the stores already encrypted with " +
			"the passphrase readable, set its SHA-256 instead - the 64 hex characters printf %s \"$PASSPHRASE\" | " +
			"sha256sum prints: it is the same key, written out")
	}
	// Ingest is the write side: an open one lets anyone inject nodes and edges, which
	// fabricates attack paths that do not exist or buries ones that do.
	if cfg.IngestHMACSecret == "" && cfg.IngestHMACSecrets == "" {
		return errors.New("PG_ENV=production but ingest authentication is disabled: refusing to start with open " +
			"ingest endpoints, which would let anyone forge the graph this tool reasons over. Set " +
			"INGEST_HMAC_SECRET (or INGEST_HMAC_SECRETS for per-tenant keys)")
	}
	return nil
}

// checkAuthConfig enforces the fail-closed rules that hold in EVERY environment, not
// just a declared production one - which is why it is separate from
// checkProductionConfig rather than folded into it.
//
// A JWT verifier that skips issuer and audience accepts any token its IdP ever minted,
// including tokens issued to a DIFFERENT relying party sharing the same JWKS. That is a
// confused deputy: another application's user becomes this application's user, carrying
// whatever role and tenant claims their token happens to have. It is not a
// production-only concern - a staging deployment wired to the corporate IdP has exactly
// the same hole - so the refusal is unconditional.
func checkAuthConfig(cfg config.Config) error {
	if cfg.OIDCJWKSURL != "" && (cfg.OIDCIssuer == "" || cfg.OIDCAudience == "") {
		return errors.New("OIDC enabled (OIDC_JWKS_URL set) but OIDC_ISSUER and/or OIDC_AUDIENCE is empty: " +
			"refusing to start without iss/aud validation. Set both, or unset OIDC_JWKS_URL to use static API_TOKENS")
	}
	return nil
}

// checkSecretConfig refuses to start when a secret was requested from a file that could
// not be read.
//
// This is the whole reason the <KEY>_FILE support is worth having. An operator who mounts
// a Docker or Kubernetes secret and mistypes the path has, from the process's point of
// view, simply not set that credential - and "no ingest HMAC key" or "no API token" is
// not an error, it is the demo profile. So the mistake would start cleanly and serve an
// open endpoint, which is precisely the outcome the operator was trying to avoid by using
// a mounted secret in the first place.
func checkSecretConfig(cfg config.Config) error {
	if len(cfg.SecretErrors) == 0 {
		return nil
	}
	return errors.New("refusing to start: a secret was requested from a file that could not be read - " +
		strings.Join(cfg.SecretErrors, "; ") +
		". Fix the path or the file's permissions, or unset the *_FILE variable to read the value from the environment")
}

// Governance pool ceiling. Six stores share this pool; the analyzer and the API are the
// only writers and their work is short. 16 is comfortably above what they need and far
// enough below a default max_connections that several replicas coexist without tuning.
const (
	govMaxOpenConns = 16
	govMaxIdleConns = 4
)

func run(parent context.Context, cfg config.Config) error {
	// fatal stops the process with an error, for a failure nothing inside it will
	// recover from: a listener that could not bind, a bus connection that closed for
	// good, a consumer that stopped. Each of those used to be one log line while the
	// process stayed up without that part of itself - and the orchestrator, seeing a
	// live process, never restarted it.
	ctx, fatal := context.WithCancelCause(parent)
	defer fatal(nil)
	var cl closers
	defer cl.close()

	tokens, err := checkStartup(cfg)
	if err != nil {
		return err
	}

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
	cl.add(func() { _ = manager.Close() })

	// ── Event bus ───────────────────────────────────────────────────
	bus, err := broker.Connect(ctx, cfg.NATSURL, cfg.NATSStream, cfg.NATSSubject, broker.Options{
		TLS: broker.TLSConfig{
			CAFile:   cfg.NATSTLSCAFile,
			CertFile: cfg.NATSTLSCertFile,
			KeyFile:  cfg.NATSTLSKeyFile,
		},
		User:     cfg.NATSUser,
		Password: cfg.NATSPassword,
		MaxAge:   cfg.NATSMaxAge,
		OnClosed: fatal,
	})
	if err != nil {
		return err
	}
	cl.add(bus.Close)

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
	// The merge gate applies a change to a copy of the graph (POST /gate/impact). It goes
	// through a normalizer configured as this one is - the same threat intel, the same
	// secret scrubbing - so it lands as the ingest path would land it; only the full-text
	// index is left out, because nothing of a dry run may leave it.
	gateNormalizer := func(m *graph.Manager) *normalization.Normalizer {
		return normalization.New(m).WithThreatIntel(intel).WithScrub(cfg.ScrubIngest)
	}

	sinks, attribution, repoAllow, err := newSinks(cfg)
	if err != nil {
		return err
	}
	notifier := notify.New(cfg.AlertWebhookURL, cfg.AlertWebhookFormat)
	if notifier.Enabled() {
		slog.Info("drift alerting: webhook enabled", "format", cfg.AlertWebhookFormat)
	}

	elector := newLeader(cfg, backend, &cl)
	sealer, exportSigner, err := newSealers(cfg)
	if err != nil {
		return err
	}
	govDB, err := openGovernancePool(ctx, cfg, &cl)
	if err != nil {
		return err
	}
	historyStore, err := openHistory(cfg, govDB, sealer)
	if err != nil {
		return err
	}
	analyzerSvc := newAnalyzer(cfg, manager, sinks, notifier, elector, historyStore, attribution)

	// ── Agentless connectors (optional; PULL from external systems) ──
	// Leader-only, so replicas don't multiply API calls. Feeds the same bus as the
	// push webhooks, so the whole downstream pipeline is reused.
	connSched := buildConnectors(ctx, cfg, bus, elector)
	if connSched.Enabled() {
		slog.Info("agentless connectors enabled", "interval", cfg.ConnectorInterval)
	}

	auditRec, err := openAuditLog(ctx, cfg, govDB, sealer, elector, &cl)
	if err != nil {
		return err
	}
	exfilWatcher, authGuard, err := newWatchers(ctx, cfg, govDB, auditRec)
	if err != nil {
		return err
	}
	ips, hmac, err := newIngestAuth(cfg)
	if err != nil {
		return err
	}
	authn, err := newAuthn(cfg, tokens)
	if err != nil {
		return err
	}
	ingestLimiter, apiLimiter, aiLimiter := newLimiters(cfg, ips)
	suppressStore, ticketStore, validationStore, err := openGovernanceStores(cfg, govDB, sealer)
	if err != nil {
		return err
	}
	if err := startKEVHoldout(ctx, cfg, intel, govDB, validationStore, manager); err != nil {
		return err
	}
	// Sample the calibration trend each analyzer pass, so the dashboard can show the
	// evidence accumulating over a calibration program (Brier/ECE/samples over time).
	analyzerSvc.WithCalibrator(func(tenant string) (float64, float64, int) {
		c, cerr := validationStore.Calibration(ctx, tenant)
		if cerr != nil {
			slog.Warn("calibration sample skipped", "tenant", tenant, "err", cerr)
			return 0, 0, 0
		}
		return c.Brier, c.ECE, c.Samples
	})

	// One store shared by the ingest path (which records what arrived) and the API
	// (which reports it), so an empty board can say what it was actually built from.
	coverageStore := coverage.New().WithStaleAfter(cfg.CoverageStaleAfter)

	ingestSrv := ingestion.NewServer(bus, ingestCollectors()...).
		WithHMAC(hmac).WithAudit(auditRec).WithRateLimit(ingestLimiter).
		WithConnectorStatus(func() any { return connSched.Status() }).
		WithCoverage(coverageStore)
	prOpener := action.NewGitHubPROpener(action.GitHubConfig{Token: cfg.GitHubToken, BaseURL: cfg.GitHubAPIURL, DryRun: cfg.GitHubDryRun, Allow: repoAllow})
	aiCfg := ai.Config{
		APIKey: cfg.AnthropicAPIKey, Model: cfg.AnthropicModel, BaseURL: cfg.AnthropicBaseURL, MaxTokens: cfg.AIMaxTokens,
		HFToken: cfg.HFToken, HFModel: cfg.HFModel, HFBaseURL: cfg.HFBaseURL,
	}
	aiClient := ai.New(aiCfg)
	if aiClient.Enabled() {
		provider, model := ai.Provider(aiCfg)
		slog.Info("AI-native layer enabled", "provider", provider, "model", model)
	}
	apiHandler, err := buildAPI(manager, analyzerSvc, indexer, authn, auditRec, apiLimiter, suppressStore, historyStore, ticketStore, validationStore, cfg.CORSAllowedOrigins, exportSigner, exfilWatcher, authGuard, authInfoFromConfig(cfg, authn.Enabled()), prOpener, aiClient, aiLimiter, bus, coverageStore, degradedReason(backend, cfg.Env), cfg.MetricsAddr != "", ips, cfg.GraphQLIntrospection, gateNormalizer)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	startWorkers(ctx, &wg, fatal, cfg, bus, normalizer, analyzerSvc, connSched)
	serve(ctx, &wg, fatal, cfg, ingestSrv, apiHandler, backend)

	<-ctx.Done()
	if parent.Err() != nil {
		slog.Info("signal received, draining…")
		wg.Wait()
		return nil
	}
	cause := context.Cause(ctx)
	slog.Error("stopping: a component failed and will not recover in this process", "err", cause)
	wg.Wait()
	return cause
}

// buildConnectors assembles the enabled agentless connectors into a leader-gated
// scheduler. Unknown names are skipped with a warning, and a connector that fails
// to initialize is skipped (not fatal) so one misconfigured source can't block
// boot. The scheduler is a no-op when nothing is enabled.
// auditRetention prunes audit records older than the retention window, until ctx ends.
//
// Leader-gated for the same reason every other side effect is: N replicas pruning the
// same chain would serialise on the audit lock and do the same work N times. The cadence
// is derived from the window rather than configured - a sixth of it, so a 90-day
// retention checks in daily - and clamped so neither a very short nor a very long window
// turns into a hot loop or a prune that effectively never runs.
func auditRetention(ctx context.Context, log *audit.PGLog, window time.Duration, elector analyzer.Leader) {
	every := window / 6
	if every < time.Hour {
		every = time.Hour
	}
	if every > 24*time.Hour {
		every = 24 * time.Hour
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !elector.IsLeader(ctx) {
				continue
			}
			removed, err := log.PruneBefore(ctx, time.Now().Add(-window))
			if err != nil {
				slog.Error("audit retention: prune failed", "err", err)
				continue
			}
			if removed > 0 {
				metrics.AuditPrunedRecords.Add(float64(removed))
				slog.Info("audit retention: pruned records older than the window",
					"removed", removed, "retention", window)
			}
		}
	}
}

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
		case "azure":
			c, err := azureconn.NewFromConfig(ctx, azureconn.Config{
				Mode:        cfg.AzureConnectorMode,
				FixturesDir: cfg.AzureFixturesDir,
			})
			if err != nil {
				slog.Error("azure connector disabled", "err", err)
				continue
			}
			slog.Info("azure connector enabled", "mode", c.Mode())
			conns = append(conns, c)
		case "kubernetes":
			c, err := k8sconn.NewFromConfig(k8sconn.Config{
				Mode:        cfg.K8SConnectorMode,
				Cluster:     cfg.K8SClusterName,
				Account:     cfg.K8SAWSAccount,
				FixturesDir: cfg.K8SFixturesDir,
			})
			if err != nil {
				slog.Error("kubernetes connector disabled", "err", err)
				continue
			}
			slog.Info("kubernetes connector enabled", "mode", c.Mode(), "cluster", cfg.K8SClusterName)
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
// in-memory stores for zero-dependency local dev - UNLESS GRAPH_STRICT is set,
// in which case it returns an error and the process refuses to start rather than
// silently dropping persistence (data that "works" in the demo but is lost on
// restart is its own kind of incident).
// backendMemoryDegraded names the graph backend when Apache AGE was unreachable and the
// engine fell back to memory. It is a constant rather than a literal in two places
// because the health signal depends on the two agreeing: if the producer's spelling
// drifted from the consumer's, degradedReason would return "" forever and /healthz would
// go back to reporting a broken engine as healthy - silently, and with every test still
// passing.
const backendMemoryDegraded = "memory-degraded"

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
	// Fail-closed in a declared production deployment, for the same reason every other
	// gate here does: the degraded mode does not look degraded. Falling back leaves the
	// engine computing over an empty, volatile graph, and an empty graph yields "no
	// attack paths" - which reads as good news. That is the precise failure this product
	// exists to make visible, arriving one layer below where ingestCoverage can see it,
	// with only a warning scrolling past to say so.
	if isProduction(cfg.Env) {
		return nil, "", fmt.Errorf("PG_ENV=production but Apache AGE is unavailable, and falling back to "+
			"in-memory stores would silently discard the graph while still reporting healthy - so an empty "+
			"board would read as \"no attack paths\" rather than \"no database\". Fix POSTGRES_DSN / the "+
			"database, or set PG_ENV=demo to accept the in-memory fallback: %w", err)
	}
	slog.Warn("Apache AGE UNAVAILABLE - falling back to IN-MEMORY stores (data is NOT persisted; set GRAPH_STRICT=true to fail instead)", "err", err)
	return func(context.Context, string) (graph.Store, error) {
		return memory.New(), nil
	}, backendMemoryDegraded, nil
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

// configuredTenants lists every tenant the configuration names, as written: the per-tenant
// ingest secrets, the API tokens and the connectors' tenant.
func configuredTenants(cfg config.Config, tokens *auth.TokenStore) []string {
	var out []string
	for _, entry := range strings.Split(cfg.IngestHMACSecrets, ",") {
		if tenant, secret, ok := strings.Cut(strings.TrimSpace(entry), ":"); ok && tenant != "" && secret != "" {
			out = append(out, tenant)
		}
	}
	out = append(out, tokens.Tenants()...)
	if cfg.ConnectorTenant != "" {
		out = append(out, cfg.ConnectorTenant)
	}
	return out
}

// servesSeveralTenants reports whether the configuration names a tenant besides the
// default. There, a token that names no tenant cannot be read as the default tenant's.
func servesSeveralTenants(cfg config.Config, tokens *auth.TokenStore) bool {
	for _, t := range configuredTenants(cfg, tokens) {
		if graph.NormalizeTenant(t) != graph.DefaultTenant {
			return true
		}
	}
	return false
}

// checkTenantNames refuses two names that become one tenant. The engine keys a tenant's
// graph, its ingest secret and its analysis by the normalized name ([a-z0-9_]), so
// "acme-corp" and "acme.corp" are one graph: two customers named that way would read each
// other's attack paths, and the second ingest secret silently replaced the first. A
// difference of case alone is the same name written twice, and stays accepted.
func checkTenantNames(cfg config.Config, tokens *auth.TokenStore) error {
	// Two ingest secrets for one tenant, in any case, are never meant: the second replaces
	// the first, and whoever signs with the first is refused.
	secretOf := map[string]string{}
	if cfg.IngestHMACSecret != "" {
		secretOf[graph.DefaultTenant] = "INGEST_HMAC_SECRET"
	}
	for _, entry := range strings.Split(cfg.IngestHMACSecrets, ",") {
		if tenant, secret, ok := strings.Cut(strings.TrimSpace(entry), ":"); ok && tenant != "" && secret != "" {
			n := graph.NormalizeTenant(tenant)
			if prev, dup := secretOf[n]; dup {
				return fmt.Errorf("two ingest secrets for tenant %q - %s and %q in INGEST_HMAC_SECRETS: the second "+
					"would replace the first, and a sender signing with the first would be refused", n, prev, tenant)
			}
			secretOf[n] = fmt.Sprintf("%q in INGEST_HMAC_SECRETS", tenant)
		}
	}

	spelling := map[string]string{}
	for _, t := range configuredTenants(cfg, tokens) {
		n := graph.NormalizeTenant(t)
		if prev, ok := spelling[n]; ok && !strings.EqualFold(strings.TrimSpace(prev), strings.TrimSpace(t)) {
			return fmt.Errorf("tenants %q and %q are one tenant to the engine - both become %q, so they would "+
				"share one graph and one ingest secret. Spell each tenant one way, best in lower case with "+
				"[a-z0-9_] only, in INGEST_HMAC_SECRETS, API_TOKENS and CONNECTOR_TENANT", prev, t, n)
		}
		spelling[n] = t
	}
	return nil
}

// authInfoFromConfig builds the public auth config the dashboard's login gate
// reads (GET /auth/config). It carries no secrets - only whether a credential is
// required and the IdP's public coordinates for an SSO redirect.
func authInfoFromConfig(cfg config.Config, authEnabled bool) api.AuthInfo {
	// "Required" is what the dashboard's login gate reads, and it means one thing: will an
	// anonymous call be rejected? With API_ANONYMOUS_ROLE set it will not - so a published
	// instance must report false, or the gate would ask a visitor for a credential the
	// deployment does not want and the API does not need. Mode still describes what a
	// credential WOULD be, because an admin signing in to the same instance is exactly how
	// its owner works on it.
	info := api.AuthInfo{Required: authEnabled && cfg.APIAnonymousRole == "", Mode: "none"}
	if !authEnabled {
		return info
	}
	info.AnonymousRole = cfg.APIAnonymousRole
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
			LogoutURL:    cfg.OIDCLogoutURL,
		}
	}
	return info
}

func buildAPI(manager *graph.Manager, svc *analyzer.Service, idx search.Indexer, authn auth.Authenticator, rec audit.Recorder, limiter *ratelimit.Limiter, suppressStore suppress.Suppressions, historyStore history.Temporal, ticketStore ticket.Tickets, validationStore validation.Verdicts, corsOrigins []string, exportSigner *exportsign.Signer, exfilWatcher, authGuard *secwatch.Watcher, authInfo api.AuthInfo, prOpener action.PROpener, aiClient ai.Client, aiLimiter *ratelimit.Limiter, batches api.BatchTracker, coverageStore *coverage.Store, degraded string, metricsElsewhere bool, ips *clientip.Resolver, introspection string, gateNormalizer func(*graph.Manager) *normalization.Normalizer) (http.Handler, error) {
	return api.New(manager, svc, idx).WithGate(allCollectors(), gateNormalizer).WithAuth(authn, rec).WithRateLimit(limiter).WithSuppress(suppressStore).WithHistory(historyStore).WithTickets(ticketStore).WithValidation(validationStore).WithCORSOrigins(corsOrigins).WithExportSigner(exportSigner).WithAbuseWatchers(exfilWatcher, authGuard).WithClientIP(ips).WithIntrospection(introspection).WithAuthInfo(authInfo).WithRemediationPR(prOpener).WithAI(aiClient).WithAIRateLimit(aiLimiter).WithIngestBatches(batches).WithCoverage(coverageStore).WithDegraded(degraded).WithMetricsElsewhere(metricsElsewhere).Handler()
}

// serveHTTP runs srv until ctx ends. A listener that fails - a port already taken, a
// certificate it cannot read - calls fatal, because a process serving the API without
// its ingest port (or the other way round) looks healthy to every probe that checks the
// port that did bind.
func serveHTTP(ctx context.Context, wg *sync.WaitGroup, fatal func(error), name string, srv *http.Server, certFile, keyFile string) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		// HTTPS when a cert/key pair is configured, plain HTTP otherwise (TLS then
		// terminates at a reverse proxy / ingress in front). ListenAndServeTLS uses
		// srv.TLSConfig (MinVersion TLS 1.2, set by the caller).
		var err error
		if certFile != "" && keyFile != "" {
			err = srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal(fmt.Errorf("%s listener on %s: %w", name, srv.Addr, err))
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
	// The API serves HTTPS itself when a certificate is configured, and a plain-HTTP probe
	// against it failed - so the container's HEALTHCHECK marked a working backend
	// unhealthy the moment in-app TLS was turned on.
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if certFile := os.Getenv("TLS_CERT_FILE"); certFile != "" && os.Getenv("TLS_KEY_FILE") != "" {
		conf, err := selfProbeTLS(certFile)
		if err != nil {
			return err
		}
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: conf}
	}
	url := scheme + "://" + net.JoinHostPort(host, port) + "/healthz"

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

// selfProbeTLS verifies the listener the probe reaches against the process's own
// certificate: that certificate is the only root trusted, and the name checked is one it
// was issued for. The probe dials 127.0.0.1, which a certificate for the service's public
// name never covers, so a stock verification would always fail - and skipping
// verification instead would accept any server on that port. This accepts exactly one:
// the one holding this certificate's key.
func selfProbeTLS(certFile string) (*tls.Config, error) {
	raw, err := os.ReadFile(certFile) // #nosec G304 G703 -- TLS_CERT_FILE, set by whoever runs the process; the certificate this same process serves
	if err != nil {
		return nil, fmt.Errorf("read TLS_CERT_FILE: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("TLS_CERT_FILE holds no PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse TLS_CERT_FILE: %w", err)
	}
	var name string
	switch {
	case len(leaf.DNSNames) > 0:
		name = leaf.DNSNames[0]
	case len(leaf.IPAddresses) > 0:
		name = leaf.IPAddresses[0].String()
	default:
		return nil, errors.New("TLS_CERT_FILE's certificate names no DNS name or IP address to verify it against")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(raw) // the leaf, and any chain the file carries
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: name}, nil
}

// setupLogging installs the process logger.
//
// The format is a choice, not a default, because the two audiences want opposite things:
// `text` is what a person reading a terminal during `make demo` wants, and `json` is what
// every log pipeline wants. This tool EXPORTS to SIEMs for a living, so shipping logs it
// could not ingest itself was a poor look as well as a poor default for production.
func setupLogging(level, format string) {
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
	opts := &slog.HandlerOptions{Level: lvl}

	var h slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "json") {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(&requestIDHandler{inner: h}))
}

// requestIDHandler stamps request_id onto any record logged with a context that carries
// one. It works at the handler rather than the call site so a log line does not have to
// remember to correlate itself - the ones that can, do.
//
// Calls that pass no context (plain slog.Info from a background task) are untouched:
// there is no request to attribute them to, and inventing one would be worse than the
// silence.
type requestIDHandler struct{ inner slog.Handler }

func (h *requestIDHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *requestIDHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := reqid.FromContext(ctx); id != "" {
		r = r.Clone()
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.inner.Handle(ctx, r)
}

func (h *requestIDHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &requestIDHandler{inner: h.inner.WithAttrs(as)}
}

func (h *requestIDHandler) WithGroup(name string) slog.Handler {
	return &requestIDHandler{inner: h.inner.WithGroup(name)}
}

// runKEVHoldout drives the holdout on its own slow ticker: one pass per day is ample
// for a 30-day window, and it keeps the KEV/EPSS fetch off the analyzer's hot path.
// The first pass runs immediately so a fresh install starts sealing forecasts at once
// rather than a day late.
func runKEVHoldout(ctx context.Context, runner *kevholdout.Runner, manager *graph.Manager, window time.Duration) {
	// A pass a day, but never coarser than the window itself (a short test window must
	// still get several passes).
	every := 24 * time.Hour
	if window/6 < every {
		every = max(window/6, time.Minute)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		for _, tenant := range manager.Tenants() {
			store, err := manager.For(ctx, tenant)
			if err != nil {
				slog.Warn("kev holdout: graph unavailable", "tenant", tenant, "err", err)
				continue
			}
			snap, err := store.Snapshot(ctx)
			if err != nil {
				slog.Warn("kev holdout: snapshot failed", "tenant", tenant, "err", err)
				continue
			}
			cves := make([]string, 0, 64)
			for _, n := range snap.Nodes {
				if n.Label == ontology.LabelCVE && n.Name != "" {
					cves = append(cves, n.Name)
				}
			}
			res, err := runner.Run(ctx, tenant, cves)
			if err != nil {
				slog.Warn("kev holdout: pass failed", "tenant", tenant, "err", err)
				continue
			}
			if res.Sealed > 0 || res.Graded > 0 {
				slog.Info("kev holdout pass", "tenant", tenant,
					"sealed", res.Sealed, "graded", res.Graded, "entered_kev", res.Exploited, "cves", len(cves))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// degradedReason turns the chosen graph backend into the human-readable cause /healthz
// reports, or "" when nothing is wrong.
//
// The demo profile is deliberately exempt, and getting this wrong is easy. There is no
// way to ASK for the in-memory store: it is only ever reached by falling back when Apache
// AGE is unreachable. So `make run-backend` - the documented zero-dependency local path,
// no database at all - takes exactly the same branch as a production database outage.
// Marking both degraded would have made local development report unhealthy and, because
// the dashboard container waits on the backend being healthy, would have stopped it
// starting at all.
//
// The distinction is therefore the declared profile, not the store: in demo (the default)
// memory is the intended mode; a deployment that declares any other environment asked for
// a database and did not get one. Production never reaches here - it refuses to start.
func degradedReason(backend, env string) string {
	if backend != backendMemoryDegraded || !isDeclaredEnvironment(env) {
		return ""
	}
	return "graph store fell back to memory: Apache AGE was unreachable at startup, " +
		"so the graph is neither persisted nor complete and any \"no attack paths\" answer is meaningless"
}

// isDeclaredEnvironment reports whether the operator named an environment at all. An
// empty or "demo" PG_ENV is the frictionless default, where running without a database is
// a choice rather than a fault.
func isDeclaredEnvironment(env string) bool {
	e := strings.ToLower(strings.TrimSpace(env))
	return e != "" && e != "demo"
}
