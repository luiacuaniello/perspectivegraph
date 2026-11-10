package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/action"
	"github.com/luiacuaniello/perspectivegraph/internal/analyzer"
	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/broker"
	"github.com/luiacuaniello/perspectivegraph/internal/clientip"
	"github.com/luiacuaniello/perspectivegraph/internal/config"
	"github.com/luiacuaniello/perspectivegraph/internal/connector"
	"github.com/luiacuaniello/perspectivegraph/internal/cryptostore"
	"github.com/luiacuaniello/perspectivegraph/internal/exportsign"
	"github.com/luiacuaniello/perspectivegraph/internal/graph"
	"github.com/luiacuaniello/perspectivegraph/internal/history"
	"github.com/luiacuaniello/perspectivegraph/internal/impact"
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
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
	"github.com/luiacuaniello/perspectivegraph/internal/suppress"
	"github.com/luiacuaniello/perspectivegraph/internal/threatintel"
	"github.com/luiacuaniello/perspectivegraph/internal/ticket"
	"github.com/luiacuaniello/perspectivegraph/internal/validation"
)

// The phases run goes through to start the engine, in the order it calls them. Each one
// builds what the later ones need and returns it. What stays open until the process
// stops is closed through closers: a defer inside a phase would close it as soon as the
// phase returned.

// closers are the cleanups run makes when it returns, newest first - as defers would.
type closers []func()

func (c *closers) add(f func()) { *c = append(*c, f) }

func (c closers) close() {
	for i := len(c) - 1; i >= 0; i-- {
		c[i]()
	}
}

// checkStartup validates the deployment profile before anything is touched, and builds the
// API token store the checks need.
func checkStartup(cfg config.Config) (*auth.TokenStore, error) {
	// Validate the deployment profile before touching any dependency. The secret files
	// first: a file that could not be read is the reason a credential is missing, and
	// checked later it was hidden behind the consequence - a 600 API_TOKENS_FILE on Linux
	// stopped the process with "no API credential is configured", which sends the operator
	// to a credential they did configure.
	if err := checkSecretConfig(cfg); err != nil {
		return nil, err
	}
	if err := checkProductionConfig(cfg); err != nil {
		return nil, err
	}
	if err := checkAuthConfig(cfg); err != nil {
		return nil, err
	}
	tokens := auth.NewTokenStore(cfg.APITokens)
	if err := checkTenantNames(cfg, tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// newSinks builds where the analyzer's findings go - the console and the forges, each held
// to REPO_ALLOWLIST - and the ledger that attributes routes to commits.
func newSinks(cfg config.Config) (action.MultiSink, *impact.Ledger, *action.RepoAllow, error) {
	// Where the engine is allowed to write. The forge writers take their destination
	// from an ingested node property, so without this they write wherever the graph
	// points - see internal/action/repoguard.go. A bad pattern fails startup rather
	// than silently dropping a repository from the list.
	repoAllow, err := action.NewRepoAllow(cfg.RepoAllowlist)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("REPO_ALLOWLIST: %w", err)
	}
	if !repoAllow.Configured() && (cfg.GitHubToken != "" || cfg.GitLabToken != "") {
		slog.Warn("forge token set but REPO_ALLOWLIST is empty: every PR comment, commit status and remediation PR will be refused",
			"fix", "set REPO_ALLOWLIST=owner/repo[,owner/*]")
	}
	// Which routes the engine's commit status and PR comments count against a commit: by
	// default the merge gate's rule - what the change opened or made likelier - which
	// needs a ledger watching every pass; "commit" is the rule before 1.22.
	var attribution *impact.Ledger
	switch cfg.PRAttribution {
	case "diff":
		attribution = impact.NewLedger()
	case "commit":
	default:
		return nil, nil, nil, fmt.Errorf("PR_ATTRIBUTION %q is not diff|commit", cfg.PRAttribution)
	}
	sinks := action.MultiSink{
		action.ConsoleSink{},
		action.NewGitHubCommenter(action.GitHubConfig{
			Token:       cfg.GitHubToken,
			BaseURL:     cfg.GitHubAPIURL,
			DryRun:      cfg.GitHubDryRun,
			Allow:       repoAllow,
			Attribution: attribution,
		}),
		action.NewGitHubChecker(action.GitHubConfig{
			Token:       cfg.GitHubToken,
			BaseURL:     cfg.GitHubAPIURL,
			DryRun:      cfg.GitHubDryRun,
			Allow:       repoAllow,
			Attribution: attribution,
		}, cfg.DashboardURL),
		action.NewGitLabCommenter(action.GitLabConfig{
			Token:       cfg.GitLabToken,
			BaseURL:     cfg.GitLabAPIURL,
			DryRun:      cfg.GitLabDryRun,
			Allow:       repoAllow,
			Attribution: attribution,
		}),
	}
	return sinks, attribution, repoAllow, nil
}

// newLeader is the leader election that gates at-most-once external actions.
func newLeader(cfg config.Config, backend string, cl *closers) analyzer.Leader {
	// Leader election gates at-most-once external actions (drift alerts, PR
	// comments) so multiple replicas don't duplicate them. With Apache AGE we use
	// a Postgres advisory lock; in-memory (single process) is always the leader.
	var elector analyzer.Leader = leader.AlwaysLeader{}
	if backend == "apache-age" {
		if pgLeader, err := leader.NewPostgres(cfg.PostgresDSN, "analyzer"); err != nil {
			slog.Warn("leader election unavailable, defaulting to always-leader", "err", err)
		} else {
			cl.add(func() { _ = pgLeader.Close() })
			elector = pgLeader
		}
	}
	return elector
}

// newSealers builds the at-rest encryption of the governance stores and the audit log, and
// the signer of the exports.
func newSealers(cfg config.Config) (cryptostore.Sealer, *exportsign.Signer, error) {
	// At-rest encryption for the file-backed governance stores + audit log. The
	// tool's persisted state is a map of how to attack the org plus who viewed it,
	// so a stolen volume/backup shouldn't surrender it in plaintext. Empty key →
	// Nop (plaintext), with a warning.
	sealer, err := cryptostore.New(cfg.StoreEncryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("store encryption: %w", err)
	}
	if sealer.Enabled() {
		slog.Info("at-rest encryption: governance stores + audit log are AES-256-GCM encrypted")
	}
	if cryptostore.IsPassphrase(cfg.StoreEncryptionKey) {
		slog.Warn("STORE_ENCRYPTION_KEY is a passphrase: it becomes the key through a single SHA-256, so an " +
			"encrypted backup can be attacked at hashing speed. Use 64 hex characters (openssl rand -hex 32); " +
			"PG_ENV=production refuses a passphrase")
	}

	// Ed25519 export signing: OSCAL/SIEM exports leave the trust boundary, so a
	// consumer should be able to verify integrity + origin. Empty key → unsigned.
	exportSigner, err := exportsign.New(cfg.ExportSigningKey)
	if err != nil {
		return nil, nil, fmt.Errorf("export signing: %w", err)
	}
	if exportSigner.Enabled() {
		slog.Info("export signing: OSCAL/SIEM exports are Ed25519-signed", "pubkey_at", "GET /export/pubkey")
	}
	return sealer, exportSigner, nil
}

// openGovernancePool opens the one pool every governance store shares when
// GOVERNANCE_BACKEND=postgres: they share a database, and a pool per store multiplies
// connections by the number of stores for no benefit. It is nil when the file backend is in
// use, which is what the stores branch on.
func openGovernancePool(ctx context.Context, cfg config.Config, cl *closers) (*sql.DB, error) {
	var govDB *sql.DB
	if cfg.GovernanceBackend == "postgres" {

		db, derr := sql.Open("postgres", cfg.PostgresDSN)
		if derr != nil {
			return nil, fmt.Errorf("governance store: %w", derr)
		}
		cl.add(func() { _ = db.Close() })
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
			return nil, fmt.Errorf("governance store: %w", merr)
		}
		slog.Info("governance stores: postgres-backed (replicas may exceed 1)", "migrations_applied", applied)
		govDB = db
	}
	return govDB, nil
}

// openHistory opens the temporal history: one store, shared - the analyzer writes each pass,
// the API reads it.
func openHistory(cfg config.Config, govDB *sql.DB, sealer cryptostore.Sealer) (history.Temporal, error) {
	var historyStore history.Temporal
	if govDB != nil {
		pgHistory, herr := history.NewPG(govDB, 0, 0)
		if herr != nil {
			return nil, fmt.Errorf("history store: %w", herr)
		}
		historyStore = pgHistory
		slog.Info("history store: postgres-backed")
	} else {
		fileHistory, herr := history.New(cfg.HistoryPath, history.WithSealer(sealer))
		if herr != nil {
			return nil, fmt.Errorf("history store: %w", herr)
		}
		historyStore = fileHistory
	}
	if historyStore.Persistent() {
		slog.Info("history store: file-backed", "path", cfg.HistoryPath)
	} else {
		slog.Warn("history store: in-memory only - path age / MTTR / trend reset on restart (set HISTORY_PATH to persist)")
	}
	return historyStore, nil
}

// newAnalyzer builds the attack-path analyzer and sets the model knobs it reads.
func newAnalyzer(cfg config.Config, manager *graph.Manager, sinks action.MultiSink, notifier notify.Notifier, elector analyzer.Leader, historyStore history.Temporal, attribution *impact.Ledger) *analyzer.Service {
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
	if attribution != nil {
		// Not passed when nil: a nil *Ledger in the interface would be a non-nil observer.
		analyzerSvc.WithPassObserver(attribution)
	}
	if cfg.GraphTTL > 0 {
		slog.Info("staleness pruning enabled - assets not re-observed within the TTL are removed (leader only)", "ttl", cfg.GraphTTL)
	}
	if cfg.AnalyzerIncremental {
		slog.Info("incremental analysis enabled - patching a resident snapshot with per-pass deltas instead of re-reading the whole graph")
	}
	if cfg.AnalyzerWorkers > 0 {
		slog.Info("analyzer pathfinding parallelism pinned", "workers", cfg.AnalyzerWorkers)
	}
	return analyzerSvc
}

// openAuditLog opens the tamper-evident audit log, or a recorder that records nothing when
// none is configured.
func openAuditLog(ctx context.Context, cfg config.Config, govDB *sql.DB, sealer cryptostore.Sealer, elector analyzer.Leader, cl *closers) (audit.Recorder, error) {
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
				return nil, aerr
			}
			// Closing drains what is still queued: the log appends asynchronously so a
			// burst of denials cannot stall the request path, and a shutdown that
			// skipped this would discard the tail of the trail.
			cl.add(func() { _ = alog.Close() })
			auditRec = alog
			slog.Info("audit log enabled (postgres, shared chain)")
			if cfg.AuditRetention > 0 {
				go auditRetention(ctx, alog, cfg.AuditRetention, elector)
				slog.Info("audit retention enabled - records older than this are pruned, oldest first (leader only)",
					"retention", cfg.AuditRetention)
			}
		} else {
			if cfg.AuditRetention > 0 {
				slog.Warn("AUDIT_RETENTION is set but the audit log is file-backed, so nothing prunes it - " +
					"rotate the file (see docs/OPERATIONS.md) or set GOVERNANCE_BACKEND=postgres")
			}
			alog, aerr := audit.Open(cfg.AuditLogPath, audit.WithSealer(sealer))
			if aerr != nil {
				return nil, aerr
			}
			cl.add(func() { _ = alog.Close() })
			auditRec = alog
			slog.Info("audit log enabled", "path", cfg.AuditLogPath)
		}
	}
	return auditRec, nil
}

// newWatchers builds the abuse watchers: exfiltration of the attack map, and auth brute force.
// A 0 threshold disables. Alerts are logged (WARN) and written to the audit log - ship those
// to your SIEM for paging.
func newWatchers(ctx context.Context, cfg config.Config, govDB *sql.DB, auditRec audit.Recorder) (exfil, lockout *secwatch.Watcher, err error) {
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
		// Durable lockouts when there is a database to keep them in. Without one the
		// lockout is per-process and per-replica, so a deploy - a schedule anyone can
		// read - hands a brute-forcer a clean slate. Only the lockout is stored, never
		// the per-failure counter: a write per failed login would let the abuse drive
		// the writes.
		if govDB != nil {
			trips, terr := secwatch.NewPGTrips(ctx, govDB)
			if terr != nil {
				return nil, nil, fmt.Errorf("auth lockout store: %w", terr)
			}
			authGuard.WithTripStore(trips)
			slog.Info("auth brute-force lockout enabled (durable, shared across replicas)",
				"threshold_failures_per_5m", cfg.AuthLockoutThreshold)
		} else {
			slog.Info("auth brute-force lockout enabled (in-memory: cleared on restart, per-replica)",
				"threshold_failures_per_5m", cfg.AuthLockoutThreshold)
		}
	}
	return exfilWatcher, authGuard, nil
}

// newIngestAuth builds the client-address resolver every per-IP control keys on, and the
// ingest signature verifier.
func newIngestAuth(cfg config.Config) (*clientip.Resolver, *auth.HMACVerifier, error) {
	// One resolver decides which address every per-IP control keys on - the rate
	// limiter, the brute-force lockout and the audit trail alike. They used to decide
	// separately and disagreed, which is how a spoofed header walked past the lockout.
	ips, err := clientip.New(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, nil, err
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
	hmac := auth.NewHMACVerifier(hmacSecrets(cfg), 32<<20, ips).WithAcceptV1(cfg.IngestHMACAcceptV1)
	if hmac.Enabled() {
		slog.Info("ingest auth: per-tenant HMAC signature required")
	} else {
		slog.Warn("ingest auth DISABLED - webhook endpoints are open (set INGEST_HMAC_SECRET)")
	}
	return ips, hmac, nil
}

// newAuthn builds the API's authenticators: API tokens, OIDC, and anonymous read access when
// the operator asks for it.
func newAuthn(cfg config.Config, tokens *auth.TokenStore) (auth.Chain, error) {
	// Group -> role mapping. A malformed entry is dropped and said out loud: silently
	// ignoring it would leave a group granting nothing, which reads as a working
	// configuration to whoever wrote it and as a broken login to whoever is locked out.
	groupRoles, mapErrs := auth.ParseGroupRoles(cfg.OIDCGroupRoles)
	for _, e := range mapErrs {
		slog.Error("OIDC_GROUP_ROLES: entry ignored", "problem", e)
	}
	if len(groupRoles) > 0 {
		slog.Info("OIDC group mapping active", "groups", len(groupRoles), "claim", cmp.Or(cfg.OIDCGroupsClaim, "groups"))
	}

	// A default role is how an operator says "anyone my IdP authenticates may look".
	// It stays none unless they say it: passing the IdP proves identity, not that the
	// subject may read a map of how to attack the organisation.
	var defaultRole auth.Role
	if cfg.OIDCDefaultRole != "" {
		r, ok := auth.ParseRole(cfg.OIDCDefaultRole)
		if !ok {
			return nil, fmt.Errorf("OIDC_DEFAULT_ROLE %q is not viewer|operator|admin", cfg.OIDCDefaultRole)
		}
		defaultRole = r
		slog.Warn("OIDC_DEFAULT_ROLE is set: EVERY subject this IdP authenticates gets this role",
			"role", r.String())
	}

	// Anonymous read access, for an instance meant to be published: a public demo, or a
	// dashboard a whole company may read. Refused rather than downgraded when it names a
	// role that can write, because "API_ANONYMOUS_ROLE=admin" is a typo that would hand
	// the estate to the internet, and a silent downgrade to viewer would hide it.
	var anon *auth.Anonymous
	if cfg.APIAnonymousRole != "" {
		r, ok := auth.ParseRole(cfg.APIAnonymousRole)
		if !ok {
			return nil, fmt.Errorf("API_ANONYMOUS_ROLE %q is not a role; the only value it accepts is viewer", cfg.APIAnonymousRole)
		}
		a, err := auth.NewAnonymous(r)
		if err != nil {
			return nil, fmt.Errorf("API_ANONYMOUS_ROLE: %w", err)
		}
		anon = a
		slog.Warn("API_ANONYMOUS_ROLE is set: ANYONE who can reach this API reads this environment's attack paths without a credential",
			"role", r.String(), "writes", "still admin-only (403)")
	}

	// With more than one tenant configured, an OIDC token has to say which is its own.
	requireTenant := servesSeveralTenants(cfg, tokens)
	if requireTenant && cfg.OIDCJWKSURL != "" {
		slog.Info("OIDC: several tenants are configured, so a token without the tenant claim is refused",
			"claim", cmp.Or(cfg.OIDCTenantClaim, "tenant"))
	}

	// The iss/aud fail-closed rule is enforced by checkAuthConfig, before this
	// function runs and before the process touches any dependency.
	authn := auth.Chain{
		tokens,
		auth.NewJWTAuthenticator(auth.JWTConfig{
			JWKSURL:       cfg.OIDCJWKSURL,
			Issuer:        cfg.OIDCIssuer,
			Audience:      cfg.OIDCAudience,
			RoleClaim:     cfg.OIDCRoleClaim,
			GroupsClaim:   cfg.OIDCGroupsClaim,
			TenantClaim:   cfg.OIDCTenantClaim,
			AppsClaim:     cfg.OIDCAppsClaim,
			GroupRoles:    groupRoles,
			DefaultRole:   defaultRole,
			RequireTenant: requireTenant,
		}),
		// Last: a presented credential is decided by the authenticators above, so a
		// wrong or expired token fails instead of falling back to anonymous.
		anon,
	}
	if authn.Enabled() {
		slog.Info("API auth: bearer credential required (GraphiQL disabled)")
	} else {
		slog.Warn("API auth DISABLED - GraphQL endpoint is open (set API_TOKENS or OIDC_JWKS_URL)")
	}
	return authn, nil
}

// newLimiters builds the per-IP rate limiters of ingest, the API and the AI endpoints.
func newLimiters(cfg config.Config, ips *clientip.Resolver) (forIngest, forAPI, forAI *ratelimit.Limiter) {
	// Per-IP rate limiters (0 disables). burst = 2×rps + 1 absorbs short bursts
	// (a `make seed` fires several POSTs back-to-back) without throttling.
	ingestLimiter := ratelimit.New(cfg.IngestRateRPS, int(cfg.IngestRateRPS*2)+1).WithClientIP(ips)
	apiLimiter := ratelimit.New(cfg.APIRateRPS, int(cfg.APIRateRPS*2)+1).WithClientIP(ips)
	if ingestLimiter.Enabled() || apiLimiter.Enabled() {
		slog.Info("rate limiting enabled", "ingest_rps", cfg.IngestRateRPS, "api_rps", cfg.APIRateRPS)
	}
	// The AI endpoints get their own, much lower cap: each call is paid for. A burst of
	// a fifth of the minute's allowance lets someone ask a follow-up without waiting.
	aiLimiter := ratelimit.New(cfg.AIRatePerMin/60, max(1, int(cfg.AIRatePerMin/5))).WithClientIP(ips)
	return ingestLimiter, apiLimiter, aiLimiter
}

// openGovernanceStores opens the triage records: suppressions, tickets and red-team/BAS
// verdicts.
func openGovernanceStores(cfg config.Config, govDB *sql.DB, sealer cryptostore.Sealer) (suppress.Suppressions, ticket.Tickets, validation.Verdicts, error) {
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
			return nil, nil, nil, fmt.Errorf("suppression store: %w", serr)
		}
		suppressStore = pgSuppress
	} else {
		fileSuppress, serr := suppress.New(cfg.SuppressionsPath, suppress.WithSealer(sealer))
		if serr != nil {
			return nil, nil, nil, fmt.Errorf("suppression store: %w", serr)
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
			return nil, nil, nil, fmt.Errorf("ticket store: %w", terr)
		}
		ticketStore = pgTickets
		slog.Info("ticket store: postgres-backed")
	} else {
		fileTickets, terr := ticket.New(cfg.TicketsPath, cfg.TicketWebhookURL, ticket.WithSealer(sealer))
		if terr != nil {
			return nil, nil, nil, fmt.Errorf("ticket store: %w", terr)
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
			return nil, nil, nil, fmt.Errorf("validation store: %w", verr)
		}
		validationStore = pgVerdicts
		slog.Info("validation store: postgres-backed")
	} else {
		fileVerdicts, verr := validation.New(cfg.ValidationsPath, validation.WithSealer(sealer))
		if verr != nil {
			return nil, nil, nil, fmt.Errorf("validation store: %w", verr)
		}
		validationStore = fileVerdicts
	}
	if !validationStore.Persistent() {
		slog.Warn("validation store: in-memory only - red-team/BAS verdicts (and the calibration dataset built from them) reset on restart; set VALIDATIONS_PATH to persist for a real calibration program")
	}
	return suppressStore, ticketStore, validationStore, nil
}

// startKEVHoldout starts the KEV holdout when it is enabled: a calibration dataset that
// builds itself.
func startKEVHoldout(ctx context.Context, cfg config.Config, intel threatintel.Source, govDB *sql.DB, validationStore validation.Verdicts, manager *graph.Manager) error {
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
	return nil
}

// startWorkers starts what runs until the process stops: the normalizer that consumes the
// bus, the analyzer loop and the connector poll loop.
func startWorkers(ctx context.Context, wg *sync.WaitGroup, fatal context.CancelCauseFunc, cfg config.Config, bus *broker.Broker, normalizer *normalization.Normalizer, analyzerSvc *analyzer.Service, connSched *connector.Scheduler) {
	// Complete snapshots: once all of an ingest that described a scope in full has landed,
	// what its source no longer lists is retracted.
	if cfg.GraphSweep {
		bus.WithSweeper(normalizer.Sweep)
	} else {
		slog.Info("complete snapshots are not applied (GRAPH_SWEEP=false): assets leave the graph by GRAPH_TTL only")
	}

	// Normalization consumer: bus -> identity resolution -> graph.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := bus.Consume(ctx, normalizer.Handle); err != nil &&
			!errors.Is(err, context.Canceled) {
			fatal(fmt.Errorf("normalizer stopped: %w", err))
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
}

// serve starts the HTTP listeners: ingest, the API, and metrics on a listener of their own
// when asked.
func serve(ctx context.Context, wg *sync.WaitGroup, fatal context.CancelCauseFunc, cfg config.Config, ingestSrv *ingestion.Server, apiHandler http.Handler, backend string) {
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
	serveHTTP(ctx, wg, fatal, "ingestion", ingestHTTP, cfg.TLSCertFile, cfg.TLSKeyFile)
	serveHTTP(ctx, wg, fatal, "api", apiHTTP, cfg.TLSCertFile, cfg.TLSKeyFile)

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
		serveHTTP(ctx, wg, fatal, "metrics", metricsHTTP, "", "")
		slog.Info("metrics on a separate listener - not on the API port", "addr", cfg.MetricsAddr)
	}

	scheme := "http"
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		scheme = "https"
	}
	slog.Info("perspectivegraph running",
		"api", cfg.APIAddr, "ingest", cfg.IngestAddr, "graph", backend, "scheme", scheme)
}
