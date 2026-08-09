// Command perspectivegraph runs the full PerspectiveGraph backend: ingestion webhook,
// normalization consumer, attack-path analyzer, and GraphQL API. Each layer
// runs concurrently and is wired together through the NATS event bus.
package main

import (
	"context"
	"crypto/tls"
	"database/sql"
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
	"github.com/luiacuaniello/perspectivegraph/internal/clientip"
	"github.com/luiacuaniello/perspectivegraph/internal/config"
	"github.com/luiacuaniello/perspectivegraph/internal/connector"
	awsconn "github.com/luiacuaniello/perspectivegraph/internal/connector/aws"
	azureconn "github.com/luiacuaniello/perspectivegraph/internal/connector/azure"
	"github.com/luiacuaniello/perspectivegraph/internal/coverage"
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
	"github.com/luiacuaniello/perspectivegraph/internal/exportsign"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/age"
	"github.com/luiacuaniello/perspectivegraph/internal/graph/memory"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion/iam"
	"github.com/luiacuaniello/perspectivegraph/internal/kevholdout"
	"github.com/luiacuaniello/perspectivegraph/internal/leader"
	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
	"github.com/luiacuaniello/perspectivegraph/internal/normalization"
	"github.com/luiacuaniello/perspectivegraph/internal/notify"
	"github.com/luiacuaniello/perspectivegraph/internal/pgmigrate"
	"github.com/luiacuaniello/perspectivegraph/internal/policy"
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

// subcommands is what the binary answers to, for the "unknown subcommand" message at the
// bottom of main. A test keeps it in step with the dispatch above it, because a list that
// silently drifts is worse than no list: it tells someone their spelling was wrong when
// the command actually exists.
var subcommands = []string{
	"andprobe", "awscollect", "gate", "genload", "genverdicts", "healthz",
	"importverdicts", "ingestreal", "mcp", "redteam", "verify-audit",
}

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

	// Calibration self-test: post synthetic verdicts drawn from a known reality (a
	// scenario), so the calibration math + diagnostics can be exercised and tested in
	// development without real vulnerable infra. See runGenverdicts. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "genverdicts" {
		if err := runGenverdicts(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "genverdicts:", err)
			os.Exit(1)
		}
		return
	}

	// Merge gate: ingest one scanner report stamped with a pull request's identity, wait
	// for the engine to place it in the estate graph, and exit non-zero when the change
	// puts a sensitive asset within reach. Blocks on attack paths, not on CVE counts. Its
	// exit code is its interface, so it exits itself rather than returning. See runGate.
	if len(os.Args) >= 2 && os.Args[1] == "gate" {
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
			fmt.Fprintln(os.Stderr, "importverdicts:", err)
			os.Exit(1)
		}
		return
	}

	// Zero-cost real ingest: Trivy-scan a genuinely vulnerable image and wire the
	// minimal topology so the real CVE sits on an internet → crown-jewel path - the
	// on-ramp to calibrating on real data. See runIngestReal. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "ingestreal" {
		if err := runIngestReal(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "ingestreal:", err)
			os.Exit(1)
		}
		return
	}

	// #6 decision tool: does the environment have AND-semantics (a compromise needing
	// several prerequisites at once) or pure OR-reachability? Scans the live graph and
	// counts the AND candidates on critical paths. See runAndProbe. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "andprobe" {
		if err := runAndProbe(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "andprobe:", err)
			os.Exit(1)
		}
		return
	}

	// Real-account validation primitive: run the live AWS connector (sdk transport)
	// once and show the discovered internet-exposed seeds vs the SG-open instances the
	// route/NACL layer suppressed - the read-only "does it read my real VPC correctly?"
	// check. See runAwsCollect. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "awscollect" {
		if err := runAwsCollect(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "awscollect:", err)
			os.Exit(1)
		}
		return
	}

	// Red-team oracle: ask AWS's own policy evaluator whether the privilege-escalation
	// claims are real, applying the SCPs, boundaries and conditions the engine skips.
	// Read-only dry runs; creates nothing. See runRedteam. Exits when done.
	if len(os.Args) >= 2 && os.Args[1] == "redteam" {
		if err := runRedteam(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "redteam:", err)
			os.Exit(1)
		}
		return
	}

	// MCP server: expose the engine as tools an AI agent can call (stdio JSON-RPC).
	// stdout is the protocol channel, so this must return before any logging starts.
	if len(os.Args) >= 2 && os.Args[1] == "mcp" {
		if err := runMCP(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "mcp:", err)
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

func run(ctx context.Context, cfg config.Config) error {
	// Validate the deployment profile before touching any dependency.
	if err := checkProductionConfig(cfg); err != nil {
		return err
	}
	if err := checkAuthConfig(cfg); err != nil {
		return err
	}
	if err := checkSecretConfig(cfg); err != nil {
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
	defer manager.Close()

	// ── Event bus ───────────────────────────────────────────────────
	bus, err := broker.Connect(ctx, cfg.NATSURL, cfg.NATSStream, cfg.NATSSubject, broker.TLSConfig{
		CAFile:   cfg.NATSTLSCAFile,
		CertFile: cfg.NATSTLSCertFile,
		KeyFile:  cfg.NATSTLSKeyFile,
	})
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
	// One pool for every governance store, not one each: they share a database, and a
	// pool per store multiplies connections by the number of stores for no benefit.
	// govDB is nil when the file backend is in use, which is what the stores below
	// branch on.
	var govDB *sql.DB
	if cfg.GovernanceBackend == "postgres" {

		db, derr := sql.Open("postgres", cfg.PostgresDSN)
		if derr != nil {
			return fmt.Errorf("governance store: %w", derr)
		}
		defer func() { _ = db.Close() }()
		// Bound the pool. database/sql defaults to UNLIMITED open connections, so a
		// traffic spike across N replicas can open more connections than Postgres will
		// accept (max_connections is 100 out of the box) - and the failure lands on
		// every replica at once, including the ones that were healthy. A ceiling turns
		// that into local queuing instead of a cluster-wide outage.
		db.SetMaxOpenConns(govMaxOpenConns)
		db.SetMaxIdleConns(govMaxIdleConns)
		// Recycle connections so a failover or a rotated credential is picked up without
		// a restart, and so idle ones do not sit against the server indefinitely.
		db.SetConnMaxLifetime(30 * time.Minute)
		db.SetConnMaxIdleTime(5 * time.Minute)

		applied, merr := pgmigrate.Apply(ctx, db)
		if merr != nil {
			return fmt.Errorf("governance store: %w", merr)
		}
		slog.Info("governance stores: postgres-backed (replicas may exceed 1)", "migrations_applied", applied)
		govDB = db
	}

	var historyStore history.Temporal
	if govDB != nil {
		pgHistory, herr := history.NewPG(govDB, 0, 0)
		if herr != nil {
			return fmt.Errorf("history store: %w", herr)
		}
		historyStore = pgHistory
		slog.Info("history store: postgres-backed")
	} else {
		fileHistory, herr := history.New(cfg.HistoryPath, history.WithSealer(sealer))
		if herr != nil {
			return fmt.Errorf("history store: %w", herr)
		}
		historyStore = fileHistory
	}
	if historyStore.Persistent() {
		slog.Info("history store: file-backed", "path", cfg.HistoryPath)
	} else {
		slog.Warn("history store: in-memory only - path age / MTTR / trend reset on restart (set HISTORY_PATH to persist)")
	}

	// Threat-model priors for the attacker-profile mixture score (package-level, read
	// lock-free by the per-path scoring). Empty config keeps the built-in defaults.
	analyzer.SetAttackerProfilePriors(cfg.AttackerProfilePriors)
	// EPSS -> conditional-traversal exponent (default 1.0 = identity = EPSS as-is).
	threatintel.SetTraversalGamma(cfg.EPSSTraversalGamma)
	// Opt-in credential-origin seeds: treat IAM users as leakable-credential seeds.
	iam.SetSeedIAMUsers(cfg.SeedIAMUsers)

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
		slog.Info("staleness pruning enabled - assets not re-observed within the TTL are removed (leader only)", "ttl", cfg.GraphTTL)
	}
	if cfg.AnalyzerIncremental {
		slog.Info("incremental analysis enabled - patching a resident snapshot with per-pass deltas instead of re-reading the whole graph")
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
	// With the Postgres governance backend the chain lives in the database, so it does
	// not need a path. Gating on the path alone would have switched the audit log OFF
	// for anyone moving to Postgres - silently, which is the worst way to lose an audit
	// trail.
	if cfg.AuditLogPath != "" || govDB != nil {
		if govDB != nil {
			// Shared chain: appends serialise on an advisory lock, so several
			// replicas append to ONE chain rather than forking it.
			alog, aerr := audit.OpenPG(govDB, audit.WithSealer(sealer))
			if aerr != nil {
				return aerr
			}
			// Closing drains what is still queued: the log appends asynchronously so a
			// burst of denials cannot stall the request path, and a shutdown that
			// skipped this would discard the tail of the trail.
			defer func() { _ = alog.Close() }()
			auditRec = alog
			slog.Info("audit log enabled (postgres, shared chain)")
		} else {
			alog, aerr := audit.Open(cfg.AuditLogPath, audit.WithSealer(sealer))
			if aerr != nil {
				return aerr
			}
			defer func() { _ = alog.Close() }()
			auditRec = alog
			slog.Info("audit log enabled", "path", cfg.AuditLogPath)
		}
	}

	// ── Abuse watchers: exfiltration of the attack map + auth brute force ──
	// A 0 threshold disables. Alerts are logged (WARN) and written to the audit
	// log - ship those to your SIEM for paging.
	const watchWindow, watchCooldown = 5 * time.Minute, 15 * time.Minute
	exfilWatcher := secwatch.New(cfg.ExfilAlertThreshold, watchWindow, watchCooldown, func(key string, count int) {
		slog.Warn("ALERT: possible attack-map exfiltration", "principal", key, "paths_in_window", count)
		// No request id: this alert is about a WINDOW of events crossing a
		// threshold, not about the single request that happened to be last.
		// Attributing it to that one would point an investigation at an
		// arbitrary request instead of the pattern.
		auditRec.Record(context.Background(), "exfil.alert", "secwatch", "", "", map[string]any{"principal": key, "count": count})
	})
	if exfilWatcher.Enabled() {
		slog.Info("exfiltration alerting enabled", "threshold_paths_per_5m", cfg.ExfilAlertThreshold)
	}
	authGuard := secwatch.New(cfg.AuthLockoutThreshold, watchWindow, watchCooldown, func(key string, count int) {
		slog.Warn("ALERT: auth brute-force lockout", "remote", key, "failures_in_window", count)
		// No request id: this alert is about a WINDOW of events crossing a
		// threshold, not about the single request that happened to be last.
		// Attributing it to that one would point an investigation at an
		// arbitrary request instead of the pattern.
		auditRec.Record(context.Background(), "auth.lockout.alert", "secwatch", "", "", map[string]any{"remote": key, "count": count})
	})
	if authGuard.Enabled() {
		slog.Info("auth brute-force lockout enabled", "threshold_failures_per_5m", cfg.AuthLockoutThreshold)
	}

	// ── Auth (optional; open with a loud warning when unset) ─────────
	// One resolver decides which address every per-IP control keys on - the rate
	// limiter, the brute-force lockout and the audit trail alike. They used to decide
	// separately and disagreed, which is how a spoofed header walked past the lockout.
	ips, err := clientip.New(cfg.TrustedProxyCIDRs)
	if err != nil {
		return err
	}
	if ips.TrustsAny() {
		slog.Info("trusted proxies configured: X-Forwarded-For is honoured from them",
			"cidrs", cfg.TrustedProxyCIDRs)
	} else {
		// Not a warning: this is the safe setting. It is worth saying out loud only
		// because a deployment that IS behind a proxy and forgot to say so will key
		// every client on the proxy's address.
		slog.Info("no trusted proxies configured: per-IP controls key on the peer address and X-Forwarded-For is ignored (set TRUSTED_PROXY_CIDRS when behind a proxy)")
	}
	hmac := auth.NewHMACVerifier(hmacSecrets(cfg), 32<<20, ips)
	if hmac.Enabled() {
		slog.Info("ingest auth: per-tenant HMAC signature required")
	} else {
		slog.Warn("ingest auth DISABLED - webhook endpoints are open (set INGEST_HMAC_SECRET)")
	}
	// The iss/aud fail-closed rule is enforced by checkAuthConfig, before this
	// function runs and before the process touches any dependency.
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
		slog.Warn("API auth DISABLED - GraphQL endpoint is open (set API_TOKENS or OIDC_JWKS_URL)")
	}

	// Per-IP rate limiters (0 disables). burst = 2×rps + 1 absorbs short bursts
	// (a `make seed` fires several POSTs back-to-back) without throttling.
	ingestLimiter := ratelimit.New(cfg.IngestRateRPS, int(cfg.IngestRateRPS*2)+1).WithClientIP(ips)
	apiLimiter := ratelimit.New(cfg.APIRateRPS, int(cfg.APIRateRPS*2)+1).WithClientIP(ips)
	if ingestLimiter.Enabled() || apiLimiter.Enabled() {
		slog.Info("rate limiting enabled", "ingest_rps", cfg.IngestRateRPS, "api_rps", cfg.APIRateRPS)
	}

	// ── Triage/suppression store ─────────────────────────────────────
	//
	// GOVERNANCE_BACKEND=postgres puts these decisions where every replica can read
	// them, which is what lifts the single-replica ceiling: the file store keeps its
	// records in memory and rewrites the whole set on each change, so a second writer
	// would neither see the first's decisions nor stop overwriting them.
	var suppressStore suppress.Suppressions
	if govDB != nil {
		pgSuppress, serr := suppress.NewPG(govDB)
		if serr != nil {
			return fmt.Errorf("suppression store: %w", serr)
		}
		suppressStore = pgSuppress
	} else {
		fileSuppress, serr := suppress.New(cfg.SuppressionsPath, suppress.WithSealer(sealer))
		if serr != nil {
			return fmt.Errorf("suppression store: %w", serr)
		}
		suppressStore = fileSuppress
		if fileSuppress.Persistent() {
			slog.Info("suppression store: file-backed - single writer, keep replicas at 1", "path", cfg.SuppressionsPath)
		} else {
			slog.Warn("suppression store: in-memory only - triage decisions are lost on restart (set SUPPRESSIONS_PATH, or GOVERNANCE_BACKEND=postgres)")
		}
	}

	// ── Remediation ticketing (optional file backing + webhook) ──────
	var ticketStore ticket.Tickets
	if govDB != nil {
		pgTickets, terr := ticket.NewPG(govDB, cfg.TicketWebhookURL)
		if terr != nil {
			return fmt.Errorf("ticket store: %w", terr)
		}
		ticketStore = pgTickets
		slog.Info("ticket store: postgres-backed")
	} else {
		fileTickets, terr := ticket.New(cfg.TicketsPath, cfg.TicketWebhookURL, ticket.WithSealer(sealer))
		if terr != nil {
			return fmt.Errorf("ticket store: %w", terr)
		}
		ticketStore = fileTickets
	}
	if ticketStore.Dispatches() {
		slog.Info("ticketing: dispatching new tickets to external tracker", "webhook", cfg.TicketWebhookURL)
	} else {
		slog.Warn("ticketing: dry-run - tickets are tracked locally only (set TICKET_WEBHOOK_URL to dispatch)")
	}

	// ── Red-team / BAS validation store (optional file backing) ──────
	var validationStore validation.Verdicts
	if govDB != nil {
		pgVerdicts, verr := validation.NewPG(govDB)
		if verr != nil {
			return fmt.Errorf("validation store: %w", verr)
		}
		validationStore = pgVerdicts
		slog.Info("validation store: postgres-backed")
	} else {
		fileVerdicts, verr := validation.New(cfg.ValidationsPath, validation.WithSealer(sealer))
		if verr != nil {
			return fmt.Errorf("validation store: %w", verr)
		}
		validationStore = fileVerdicts
	}
	if !validationStore.Persistent() {
		slog.Warn("validation store: in-memory only - red-team/BAS verdicts (and the calibration dataset built from them) reset on restart; set VALIDATIONS_PATH to persist for a real calibration program")
	}

	// ── KEV holdout: a calibration dataset that builds itself ────────
	// Seals a per-CVE forecast today and grades it one window later against whether
	// that CVE entered KEV meanwhile. Opt-in, and only meaningful with threat intel on
	// (the forecast is derived from EPSS).
	if cfg.KEVHoldoutEnabled {
		switch {
		case !intel.Enabled():
			slog.Warn("kev holdout: ignored - it forecasts from EPSS, so it needs THREATINTEL=true")
		default:
			var hstore kevholdout.Holdout
			if govDB != nil {
				pgHoldout, herr := kevholdout.NewPGStore(govDB)
				if herr != nil {
					return fmt.Errorf("kev holdout store: %w", herr)
				}
				hstore = pgHoldout
			} else {
				fileHoldout, herr := kevholdout.NewStore(cfg.KEVHoldoutPath)
				if herr != nil {
					return fmt.Errorf("kev holdout store: %w", herr)
				}
				hstore = fileHoldout
			}
			if cfg.KEVHoldoutPath == "" {
				slog.Warn("kev holdout: in-memory only - a window outlives most uptimes, so no forecast will ever mature; set KEV_HOLDOUT_PATH")
			}
			runner := kevholdout.NewRunner(intel, hstore, validationStore, cfg.KEVHoldoutWindow, slog.Default())
			go runKEVHoldout(ctx, runner, manager, cfg.KEVHoldoutWindow)
			slog.Info("kev holdout enabled", "window", cfg.KEVHoldoutWindow, "persistent", cfg.KEVHoldoutPath != "")
		}
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

	ingestSrv := ingestion.NewServer(bus, allCollectors()...).
		WithHMAC(hmac).WithAudit(auditRec).WithRateLimit(ingestLimiter).
		WithConnectorStatus(func() any { return connSched.Status() }).
		WithCoverage(coverageStore)
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
	apiHandler, err := buildAPI(manager, analyzerSvc, indexer, authn, auditRec, apiLimiter, suppressStore, historyStore, ticketStore, validationStore, cfg.CORSAllowedOrigins, exportSigner, exfilWatcher, authGuard, authInfoFromConfig(cfg, authn.Enabled()), prOpener, aiClient, coverageStore, degradedReason(backend, cfg.Env), cfg.MetricsAddr != "", ips)
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
	// TLS >= 1.2 whenever a cert/key pair is configured (harmless on a plain-HTTP
	// listener - TLSConfig is only consulted by ListenAndServeTLS).
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	ingestHTTP := &http.Server{
		Addr:              cfg.IngestAddr,
		Handler:           ingestSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         tlsConf,
	}
	apiHTTP := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           apiHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         tlsConf,
	}
	serveHTTP(ctx, &wg, "ingestion", ingestHTTP, cfg.TLSCertFile, cfg.TLSKeyFile)
	serveHTTP(ctx, &wg, "api", apiHTTP, cfg.TLSCertFile, cfg.TLSKeyFile)

	// Metrics on their own listener when asked. Deliberately plain HTTP even when the
	// API speaks TLS: this is meant for an address the outside cannot reach (bind it to
	// 127.0.0.1 or a pod-internal interface), and requiring a certificate there is
	// friction that pushes operators back onto the public port - which is the thing this
	// exists to avoid. It carries only /metrics: no GraphQL, no auth config, no exports.
	if cfg.MetricsAddr != "" {
		mmux := http.NewServeMux()
		mmux.Handle("GET /metrics", metrics.Handler())
		metricsHTTP := &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           mmux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		serveHTTP(ctx, &wg, "metrics", metricsHTTP, "", "")
		slog.Info("metrics on a separate listener - not on the API port", "addr", cfg.MetricsAddr)
	}

	scheme := "http"
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		scheme = "https"
	}
	slog.Info("perspectivegraph running",
		"api", cfg.APIAddr, "ingest", cfg.IngestAddr, "graph", backend, "scheme", scheme)

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

// authInfoFromConfig builds the public auth config the dashboard's login gate
// reads (GET /auth/config). It carries no secrets - only whether a credential is
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
			LogoutURL:    cfg.OIDCLogoutURL,
		}
	}
	return info
}

func buildAPI(manager *graph.Manager, svc *analyzer.Service, idx search.Indexer, authn auth.Authenticator, rec audit.Recorder, limiter *ratelimit.Limiter, suppressStore suppress.Suppressions, historyStore history.Temporal, ticketStore ticket.Tickets, validationStore validation.Verdicts, corsOrigins []string, exportSigner *exportsign.Signer, exfilWatcher, authGuard *secwatch.Watcher, authInfo api.AuthInfo, prOpener action.PROpener, aiClient ai.Client, coverageStore *coverage.Store, degraded string, metricsElsewhere bool, ips *clientip.Resolver) (http.Handler, error) {
	return api.New(manager, svc, idx).WithAuth(authn, rec).WithRateLimit(limiter).WithSuppress(suppressStore).WithHistory(historyStore).WithTickets(ticketStore).WithValidation(validationStore).WithCORSOrigins(corsOrigins).WithExportSigner(exportSigner).WithAbuseWatchers(exfilWatcher, authGuard).WithClientIP(ips).WithAuthInfo(authInfo).WithRemediationPR(prOpener).WithAI(aiClient).WithCoverage(coverageStore).WithDegraded(degraded).WithMetricsElsewhere(metricsElsewhere).Handler()
}

func serveHTTP(ctx context.Context, wg *sync.WaitGroup, name string, srv *http.Server, certFile, keyFile string) {
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
