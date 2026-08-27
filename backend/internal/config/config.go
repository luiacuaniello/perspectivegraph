// Package config loads PerspectiveGraph configuration from environment variables
// (12-factor style). A .env file, if present, is loaded first.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// Graph core (Postgres + Apache AGE)
	PostgresDSN string
	AGEGraph    string

	// Event bus (NATS JetStream)
	NATSURL     string
	NATSStream  string
	NATSSubject string
	// NATS transport security (file paths, off by default). NATSTLSCAFile trusts a
	// private CA for server-auth TLS (use with a tls:// NATS_URL); NATSTLSCertFile +
	// NATSTLSKeyFile add a client cert for mutual TLS. Service-mesh users can leave
	// these empty and let the mesh handle it.
	NATSTLSCAFile   string
	NATSTLSCertFile string
	NATSTLSKeyFile  string

	// Env names the deployment profile. "demo" (the default) keeps the frictionless
	// path `make demo` relies on: no credentials configured means an open API, with
	// a loud warning. "production" turns that warning into a refusal to start - see
	// the fail-closed check in main. It only ever makes startup *stricter*, so an
	// unset or unknown value can never weaken anything.
	Env string

	// HTTP servers
	APIAddr    string
	IngestAddr string
	// MetricsAddr, when set, serves Prometheus /metrics on its OWN listener instead of
	// on the API's mux. Several series carry a `tenant` label, so on a reachable API
	// port they let anyone enumerate tenants and read each one's critical-path count.
	// Empty (default) keeps the historical behaviour, since /metrics on the API port is
	// declared stable surface; bind it to an internal interface in production.
	MetricsAddr string

	// TLS for the API + ingest servers. When both are set the servers speak HTTPS
	// (TLS >= 1.2) directly; empty (the default) serves plain HTTP, expecting TLS
	// to be terminated by a reverse proxy / ingress in front.
	TLSCertFile string
	TLSKeyFile  string

	// Analyzer
	AnalyzerInterval time.Duration
	AnalyzerMaxHops  int
	AnalyzerDBPaths  bool
	// AnalyzerWorkers bounds the goroutines that fan out the per-seed shortest-path
	// searches each pass. 0 (default) means auto = GOMAXPROCS. Raise/lower it to
	// trade analyzer CPU against pass latency on large graphs with many entry points.
	AnalyzerWorkers int
	// AnalyzerIncremental, when true, patches a resident snapshot with per-pass
	// deltas instead of re-reading the whole graph each pass (the fetch cost on a
	// large AGE graph). Off by default - it keeps the graph resident, trading memory
	// for fetch cost, and falls back to full reads when the store can't do deltas.
	AnalyzerIncremental bool
	// AttackerProfilePriors overrides the threat-model priors for the attacker-profile
	// mixture score, e.g. "commodity:0.5,criminal:0.35,apt:0.15". Empty keeps the
	// built-in defaults. Names match the built-in profiles; priors are renormalized.
	AttackerProfilePriors string

	// EPSSTraversalGamma is the exponent of the EPSS -> conditional-traversal map
	// p(traverse|positioned) = EPSS^gamma, applied where EPSS sets an edge probability.
	// EPSS is a marginal 30-day exploitation rate, not the conditional a positioned
	// attacker's traversal needs; gamma < 1 lifts it (correcting the known
	// under-statement), gamma = 1 (default) keeps EPSS as-is. Opt-in: no fitted map is
	// applied silently. See threatintel.EdgeProbability.
	EPSSTraversalGamma float64

	// SeedIAMUsers opts into the credential-origin threat model: when true, IAM users
	// become traversal seeds (on the premise their long-lived credentials could leak),
	// so "if a credential leaks, what does it reach" surfaces alongside the internet-
	// origin paths. Off by default, keeping the headline the internet-origin attack path.
	SeedIAMUsers bool

	// GitHub PR commenter (action layer)
	// AI-native layer. Anthropic (Claude) is the preferred backend; HuggingFace
	// (HFToken, OpenAI-compatible) is the free/self-hosted alternative used when no
	// Anthropic key is set. With neither, the /ai/* endpoints are disabled. The
	// graph is the org's attack map, so a compacted view leaves the trust boundary
	// on each call (audited): enabling AI is a deliberate opt-in.
	AnthropicAPIKey  string
	AnthropicModel   string
	AnthropicBaseURL string
	AIMaxTokens      int
	// HuggingFace / OpenAI-compatible fallback (used only when AnthropicAPIKey is
	// empty). HFToken is an HF access token (or any OpenAI-compatible key); HFModel
	// must be a chat model the token can reach; HFBaseURL defaults to the HF router.
	HFToken   string
	HFModel   string
	HFBaseURL string

	// DashboardURL, when set, deep-links a PR check back to the dashboard
	// (target_url on the GitHub status). Optional.
	DashboardURL string
	GitHubToken  string
	GitHubAPIURL string
	GitHubDryRun bool

	// GitLab MR commenter (action layer)
	GitLabToken  string
	GitLabAPIURL string
	GitLabDryRun bool

	// OpenSearch full-text index (optional)
	OpenSearchURL string

	// Threat-intel enrichment (CISA KEV + FIRST EPSS), optional
	ThreatIntelEnabled bool
	KEVFeedURL         string
	EPSSAPIURL         string

	// KEV holdout (optional; needs THREATINTEL). Seals a per-CVE forecast and grades it
	// one window later against whether that CVE entered KEV in the meantime - a
	// calibration dataset that builds itself, with no red team. Requires
	// KEV_HOLDOUT_PATH to survive restarts, since a window outlives most uptimes.
	// See internal/kevholdout for why the grading must be out-of-sample.
	// CoverageStaleAfter is when an ingest source stops counting as current. It bounds
	// the claim an empty board makes: "no path in what I was given, and this is how
	// recently I was given it".
	CoverageStaleAfter time.Duration

	KEVHoldoutEnabled bool
	KEVHoldoutPath    string
	KEVHoldoutWindow  time.Duration

	// Auth (optional; open with a warning when unset)
	IngestHMACSecret  string // HMAC secret for the default tenant
	IngestHMACSecrets string // per-tenant secrets: "tenant:secret,tenant2:secret2"
	APITokens         string // bearer tokens → role[:tenant]: "tok:viewer,tok2:admin:globex"

	// OIDC/JWT (optional API auth alongside static tokens)
	OIDCJWKSURL  string
	OIDCIssuer   string
	OIDCAudience string
	// OIDC login (SPA-facing, not secret): the dashboard's login gate uses these to
	// start an SSO Authorization-Code redirect. Validation still relies on the
	// JWKS/issuer/audience above; these only drive the "Sign in with SSO" button.
	OIDCClientID string
	OIDCAuthURL  string
	OIDCTokenURL string
	OIDCScopes   string
	// OIDCLogoutURL is the IdP end-session endpoint. When set, "Sign out" performs
	// an RP-initiated logout (redirects there) so the IdP session ends too, instead
	// of just dropping the local token and silently re-logging in on the next click.
	OIDCLogoutURL string

	// OIDC claim names and the group -> role mapping. Enterprise IdPs keep
	// authorisation in group membership, not in a bespoke "role" claim, so without
	// these an SSO user arrives with no role and sees nothing until someone builds a
	// custom claim mapping inside the IdP. OIDCDefaultRole stays empty (= no access)
	// unless an operator widens it on purpose.
	OIDCRoleClaim   string
	OIDCGroupsClaim string
	OIDCTenantClaim string
	OIDCAppsClaim   string
	OIDCGroupRoles  string // "group=role,group=role"
	OIDCDefaultRole string

	// Audit (optional; tamper-evident hash-chained log file)
	AuditLogPath string

	// AuditRetention bounds how long audit records are kept. Zero (the default) keeps
	// them forever, which is the behaviour every release so far has had - a retention
	// policy is a decision about someone's records, so it is opted into, not imposed by
	// an upgrade. It applies to the POSTGRES-backed chain, where the engine can prune a
	// prefix and leave a checkpoint that keeps what remains verifiable; the file-backed
	// chain is rotated by whatever rotates your other log files (see OPERATIONS.md).
	AuditRetention time.Duration

	// Triage/suppression store (optional; file-backed). When set, analyst
	// decisions to suppress a specific attack path (accept-risk / false-positive
	// / mitigating-control / duplicate, with owner + optional expiry) persist
	// here as JSON. Empty → in-memory only (lost on restart).
	SuppressionsPath string
	// GovernanceBackend picks where triage decisions live: "file" (default, one
	// writer) or "postgres" (shared, so the backend can run more than one replica).
	GovernanceBackend string

	// History store (optional; file-backed). When set, per-path lifecycle
	// (first/last seen, open/resolved, reopens → MTTR) and the posture trend
	// persist here as JSON, so "open for N days" and management trends survive
	// restarts. Empty → in-memory only (lost on restart).
	HistoryPath string

	// Remediation ticketing (optional). TicketsPath file-backs the local work
	// board; TicketWebhookURL dispatches each new ticket to an external tracker
	// (Jira/GitHub/SOAR). Both empty → in-memory, dry-run (logged, tracked locally).
	TicketsPath      string
	TicketWebhookURL string

	// Red-team / BAS validation store (optional; file-backed). Verdicts on whether
	// paths are real (confirmed/refuted/partial/missed) + the precision/recall they
	// imply. Empty → in-memory only.
	ValidationsPath string

	// Drift alerting (optional; chat/SOAR webhook)
	AlertWebhookURL    string
	AlertWebhookFormat string // slack | generic

	// Rate limiting (per client IP). 0 disables.
	IngestRateRPS float64
	APIRateRPS    float64

	// Graph core: when true, refuse to start if Apache AGE is unreachable
	// instead of silently falling back to the in-memory store.
	GraphStrict bool

	// GraphTTL enables staleness pruning: nodes/edges not re-observed within this
	// window are removed, so assets that left the source feeds stop generating
	// phantom attack paths. 0 (default) disables pruning.
	GraphTTL time.Duration

	// ScrubIngest redacts secret-looking values (AWS/GitHub/Slack tokens, private
	// keys, `secret=…` assignments) out of scanner output before it is stored, so
	// the attack map never persists a live credential. On by default - disable only
	// with a deliberate reason. Retention of the (scrubbed) findings is handled by
	// GraphTTL; the graph is derived and re-seedable, so nothing sensitive needs to
	// live there long-term.
	ScrubIngest bool

	// ── Agentless connectors (PULL ingestion) ───────────────────────
	// ConnectorsEnabled lists the agentless connectors to run, e.g. "aws". Empty
	// (default) runs none - ingestion stays push-only. Connectors pull from
	// external systems on a schedule (leader-only) and feed the same bus.
	ConnectorsEnabled []string
	// ConnectorInterval is how often every enabled connector pulls. Default 15m.
	ConnectorInterval time.Duration
	// ConnectorTimeout bounds a single connector's pull so one hung external call
	// can't block the others or the schedule. Default 2m.
	ConnectorTimeout time.Duration
	// ConnectorTenant routes every connector's events to this tenant's graph.
	// Default "default".
	ConnectorTenant string

	// AWS connector. AWSConnectorMode is "fixtures" (default - pull from local
	// describe-* JSON, no credentials needed) or "sdk" (live AWS). AWSFixturesDir
	// is the JSON directory for fixtures mode; AWSRegion / AWSRoleARN configure
	// sdk mode (region, plus an optional cross-account read-only role to assume).
	AWSConnectorMode string
	AWSFixturesDir   string
	AWSRegion        string
	AWSRoleARN       string

	// Azure connector. AzureConnectorMode is "fixtures" (default - pull from local
	// normalized `az network`/`az vm -o json` state, no credentials needed) or "sdk"
	// (live Azure, wired extension point). AzureFixturesDir is the JSON directory for
	// fixtures mode.
	AzureConnectorMode string
	AzureFixturesDir   string

	// CORS: browser origins allowed to call the API cross-origin. Defaults to the
	// local Vite dev server + the docker-compose dashboard. Set to "*" to allow any
	// origin (not recommended), or to your dashboard's real origin in production.
	CORSAllowedOrigins []string

	// TrustedProxyCIDRs lists the reverse proxies / ingresses in front of this service,
	// as CIDRs or bare addresses. It decides whether X-Forwarded-For may be believed.
	//
	// Empty (the default) means no proxy: per-IP controls key on the connecting peer and
	// the header is ignored. That is the safe default - a client can write any header it
	// likes, so trusting one unconditionally let a brute force rotate the header to evade
	// the account lockout, and let it name a victim's address to lock that victim out.
	//
	// Set it when a proxy really is in front, or every request will look like it came
	// from the proxy and one attacker's failures will lock out everybody at once.
	TrustedProxyCIDRs []string

	// GraphQLIntrospection controls whether __schema/__type may be queried:
	// "on", "off", or empty to follow the auth posture (on while the API is open and
	// GraphiQL is served, off once a credential is required). The schema is a complete
	// map of every query and argument the service accepts, so an authenticated
	// deployment does not hand it to every viewer-role token by default.
	GraphQLIntrospection string

	// StoreEncryptionKey encrypts the file-backed governance stores and the audit
	// log at rest (AES-256-GCM). A 64-hex-char value is the raw key; anything else
	// is a passphrase. Empty (default) → plaintext on disk.
	StoreEncryptionKey string

	// ExportSigningKey is an Ed25519 private key (64-hex seed) used to sign the
	// OSCAL/SIEM exports so a consumer can verify integrity + origin. Empty → unsigned.
	ExportSigningKey string

	// AuthLockoutThreshold: failed API auth attempts from one IP within a 5-minute
	// window before that IP is locked out (HTTP 429) for 15 minutes and an alert is
	// logged + audited. 0 disables. ExfilAlertThreshold: attack-path views/exports
	// by one principal within 5 minutes before an exfiltration alert fires. 0 disables.
	AuthLockoutThreshold int
	ExfilAlertThreshold  int

	// Observability
	// SecretErrors collects problems found while reading <KEY>_FILE secrets. Load
	// cannot return an error, so the refusal to start lives in checkSecretConfig -
	// same shape as the production and auth gates.
	SecretErrors []string

	LogLevel string
	// LogFormat is "text" (human, the demo default) or "json" (log pipelines).
	LogFormat string
}

// Load reads configuration from the environment, applying sane defaults so the
// stack runs against the bundled docker-compose with zero configuration.
func Load() Config {
	// The backend usually runs from backend/ (make run-backend), while the
	// shared .env lives at the repo root next to docker-compose: try both, so
	// one file configures everything. Real env vars always win.
	loadDotEnv(".env")
	loadDotEnv(filepath.Join("..", ".env"))

	sec := &secretReader{}
	cfg := Config{
		PostgresDSN: sec.get("POSTGRES_DSN", buildPostgresDSN(sec)),
		AGEGraph:    getenv("AGE_GRAPH_NAME", "perspective"),

		NATSURL:         getenv("NATS_URL", "nats://localhost:4222"),
		NATSStream:      getenv("NATS_STREAM", "PERSPECTIVE"),
		NATSSubject:     getenv("NATS_SUBJECT", "perspective.events.*"),
		NATSTLSCAFile:   getenv("NATS_TLS_CA", ""),
		NATSTLSCertFile: getenv("NATS_TLS_CERT", ""),
		NATSTLSKeyFile:  getenv("NATS_TLS_KEY", ""),

		Env:         getenv("PG_ENV", "demo"),
		APIAddr:     getenv("API_ADDR", ":8080"),
		IngestAddr:  getenv("INGEST_ADDR", ":8081"),
		MetricsAddr: getenv("METRICS_ADDR", ""),
		TLSCertFile: getenv("TLS_CERT_FILE", ""),
		TLSKeyFile:  getenv("TLS_KEY_FILE", ""),

		AnalyzerInterval:      getdur("ANALYZER_INTERVAL", 30*time.Second),
		AnalyzerMaxHops:       getint("ANALYZER_MAX_HOPS", 12),
		AnalyzerDBPaths:       getbool("ANALYZER_DB_PATHS", false),
		AnalyzerWorkers:       getint("ANALYZER_WORKERS", 0),
		AnalyzerIncremental:   getbool("ANALYZER_INCREMENTAL", false),
		AttackerProfilePriors: getenv("ATTACKER_PROFILE_PRIORS", ""),
		EPSSTraversalGamma:    getfloat("EPSS_TRAVERSAL_GAMMA", 1.0),
		SeedIAMUsers:          getbool("SEED_IAM_USERS", false),

		AnthropicAPIKey:  sec.get("ANTHROPIC_API_KEY", ""),
		AnthropicModel:   getenv("ANTHROPIC_MODEL", ""),
		AnthropicBaseURL: getenv("ANTHROPIC_BASE_URL", ""),
		AIMaxTokens:      getint("AI_MAX_TOKENS", 0),
		HFToken:          sec.get("HF_TOKEN", sec.get("HUGGINGFACE_API_KEY", "")),
		HFModel:          getenv("HF_MODEL", ""),
		HFBaseURL:        getenv("HF_BASE_URL", ""),

		DashboardURL: getenv("DASHBOARD_URL", ""),
		GitHubToken:  sec.get("GITHUB_TOKEN", ""),
		GitHubAPIURL: getenv("GITHUB_API_URL", "https://api.github.com"),
		GitHubDryRun: getbool("GITHUB_DRY_RUN", false),

		GitLabToken:  sec.get("GITLAB_TOKEN", ""),
		GitLabAPIURL: getenv("GITLAB_API_URL", "https://gitlab.com/api/v4"),
		GitLabDryRun: getbool("GITLAB_DRY_RUN", false),

		OpenSearchURL: getenv("OPENSEARCH_URL", ""),

		ThreatIntelEnabled: getbool("THREATINTEL", false),
		KEVFeedURL:         getenv("KEV_FEED_URL", ""),
		EPSSAPIURL:         getenv("EPSS_API_URL", ""),

		CoverageStaleAfter: getdur("COVERAGE_STALE_AFTER", 24*time.Hour),

		KEVHoldoutEnabled: getbool("KEV_HOLDOUT", false),
		KEVHoldoutPath:    getenv("KEV_HOLDOUT_PATH", ""),
		// 30 days: the horizon EPSS forecasts over, so the sealed prediction and the
		// graded question cover the same span. Kept literal rather than imported from
		// kevholdout - config imports no feature package.
		KEVHoldoutWindow: getdur("KEV_HOLDOUT_WINDOW", 30*24*time.Hour),

		IngestHMACSecret:  sec.get("INGEST_HMAC_SECRET", ""),
		IngestHMACSecrets: sec.get("INGEST_HMAC_SECRETS", ""),
		APITokens:         sec.get("API_TOKENS", ""),

		OIDCJWKSURL:   getenv("OIDC_JWKS_URL", ""),
		OIDCIssuer:    getenv("OIDC_ISSUER", ""),
		OIDCAudience:  getenv("OIDC_AUDIENCE", ""),
		OIDCClientID:  getenv("OIDC_CLIENT_ID", ""),
		OIDCAuthURL:   getenv("OIDC_AUTHORIZE_URL", ""),
		OIDCTokenURL:  getenv("OIDC_TOKEN_URL", ""),
		OIDCScopes:    getenv("OIDC_SCOPES", "openid profile email"),
		OIDCLogoutURL: getenv("OIDC_LOGOUT_URL", ""),

		OIDCRoleClaim:   getenv("OIDC_ROLE_CLAIM", ""),
		OIDCGroupsClaim: getenv("OIDC_GROUPS_CLAIM", ""),
		OIDCTenantClaim: getenv("OIDC_TENANT_CLAIM", ""),
		OIDCAppsClaim:   getenv("OIDC_APPS_CLAIM", ""),
		OIDCGroupRoles:  getenv("OIDC_GROUP_ROLES", ""),
		OIDCDefaultRole: getenv("OIDC_DEFAULT_ROLE", ""),

		AuditLogPath:      getenv("AUDIT_LOG_PATH", ""),
		AuditRetention:    getdur("AUDIT_RETENTION", 0),
		SuppressionsPath:  getenv("SUPPRESSIONS_PATH", ""),
		GovernanceBackend: getenv("GOVERNANCE_BACKEND", "file"),
		HistoryPath:       getenv("HISTORY_PATH", ""),
		TicketsPath:       getenv("TICKETS_PATH", ""),
		TicketWebhookURL:  sec.get("TICKET_WEBHOOK_URL", ""),
		ValidationsPath:   getenv("VALIDATIONS_PATH", ""),

		AlertWebhookURL:    sec.get("ALERT_WEBHOOK_URL", ""),
		AlertWebhookFormat: getenv("ALERT_WEBHOOK_FORMAT", "slack"),

		IngestRateRPS: getfloat("INGEST_RATE_RPS", 30),
		APIRateRPS:    getfloat("API_RATE_RPS", 60),
		GraphStrict:   getbool("GRAPH_STRICT", false),
		GraphTTL:      getdur("GRAPH_TTL", 0),
		ScrubIngest:   getbool("SCRUB_INGEST", true),

		ConnectorsEnabled: getlist("CONNECTORS_ENABLED", ""),
		ConnectorInterval: getdur("CONNECTOR_INTERVAL", 15*time.Minute),
		ConnectorTimeout:  getdur("CONNECTOR_TIMEOUT", 2*time.Minute),
		ConnectorTenant:   getenv("CONNECTOR_TENANT", ""),
		AWSConnectorMode:  getenv("AWS_CONNECTOR_MODE", "fixtures"),
		AWSFixturesDir:    getenv("AWS_FIXTURES_DIR", ""),
		AWSRegion:         getenv("AWS_REGION", ""),
		AWSRoleARN:        getenv("AWS_ROLE_ARN", ""),

		AzureConnectorMode: getenv("AZURE_CONNECTOR_MODE", "fixtures"),
		AzureFixturesDir:   getenv("AZURE_FIXTURES_DIR", ""),

		CORSAllowedOrigins:   getlist("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000"),
		TrustedProxyCIDRs:    getlist("TRUSTED_PROXY_CIDRS", ""),
		GraphQLIntrospection: strings.ToLower(strings.TrimSpace(getenv("GRAPHQL_INTROSPECTION", ""))),

		StoreEncryptionKey: sec.get("STORE_ENCRYPTION_KEY", ""),
		ExportSigningKey:   sec.get("EXPORT_SIGNING_KEY", ""),

		AuthLockoutThreshold: getint("AUTH_LOCKOUT_THRESHOLD", 50),
		ExfilAlertThreshold:  getint("EXFIL_ALERT_THRESHOLD", 0),

		LogLevel:  getenv("LOG_LEVEL", "info"),
		LogFormat: getenv("LOG_FORMAT", "text"),
	}
	cfg.SecretErrors = sec.errs
	return cfg
}

func buildPostgresDSN(sec *secretReader) string {
	host := getenv("POSTGRES_HOST", "localhost")
	port := getenv("POSTGRES_PORT", "5432")
	user := getenv("POSTGRES_USER", "perspective")
	pass := sec.get("POSTGRES_PASSWORD", "perspective")
	db := getenv("POSTGRES_DB", "perspectivegraph")
	// sslmode is configurable (POSTGRES_SSLMODE): the bundled in-cluster Postgres
	// has no TLS so the demo defaults to "disable", but a managed/external DB holds
	// the attack map over a real network and should set "require" (encrypt) or
	// "verify-full" (encrypt + verify the server cert). For full control of the DSN
	// (e.g. sslrootcert), set POSTGRES_DSN directly and this builder is bypassed.
	sslmode := getenv("POSTGRES_SSLMODE", "disable")
	return "host=" + host + " port=" + port + " user=" + user +
		" password=" + pass + " dbname=" + db + " sslmode=" + sslmode
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// secretReader reads values that should not have to live in the process environment.
//
// The environment is one of the least private places on a Unix box: anything that can
// read /proc/<pid>/environ sees it, `docker inspect` prints it in full to anyone in the
// docker group, it lands in crash dumps, and every child process inherits it. Kubernetes
// deployments already avoid the worst of that by sourcing values from a Secret, but the
// value still arrives as an environment variable, and Docker had no equivalent at all.
//
// So every secret also accepts <KEY>_FILE: the path to a file holding the value. That is
// the convention the postgres and mysql images established, and it is what makes Docker
// secrets, Swarm secrets, a Vault Agent sidecar and a Kubernetes Secret mounted as a
// volume all work without the value ever passing through the environment.
type secretReader struct{ errs []string }

// get prefers <KEY>_FILE, then <KEY>, then the default.
//
// A <KEY>_FILE that is set but unreadable is recorded as an ERROR rather than quietly
// falling through to <KEY> or the default. That fallback is the dangerous one: an
// operator who mounted a secret and mistyped the path would start successfully, with an
// empty credential, believing the mount had worked. For an ingest HMAC key or an API
// token that is the difference between a closed deployment and an open one.
func (s *secretReader) get(key, def string) string {
	if path := os.Getenv(key + "_FILE"); path != "" {
		b, err := os.ReadFile(path) // #nosec G304 G703 -- the path comes from <KEY>_FILE, set by whoever runs the process; anyone who can set its environment already owns it
		switch {
		case err != nil:
			s.errs = append(s.errs, key+"_FILE is set to "+path+" but it cannot be read: "+err.Error())
		case len(trimSecret(b)) == 0:
			s.errs = append(s.errs, key+"_FILE is set to "+path+" but the file is empty")
		default:
			return trimSecret(b)
		}
		return "" // never fall through to a weaker source once a file was named
	}
	return getenv(key, def)
}

// trimSecret strips the trailing newline a secret file almost always carries (`echo` and
// most secret managers add one) without touching anything else. Deliberately not
// TrimSpace: a passphrase is allowed to begin or end with a space, and silently altering
// a credential is worse than carrying a stray byte.
func trimSecret(b []byte) string {
	return strings.TrimRight(string(b), "\r\n")
}

// getlist parses a comma-separated env var into a trimmed, non-empty slice. A
// var that is present but empty yields an empty slice (an explicit "none"),
// distinct from being unset (which uses def).
func getlist(key, def string) []string {
	v, ok := os.LookupEnv(key)
	if !ok {
		v = def
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getbool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}

// getint parses an int env var, falling back to def on absence/parse error.
func getint(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// getfloat parses a float env var, falling back to def on absence/parse error.
// A negative value is kept (callers treat <=0 as "disabled").
func getfloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

// getdur parses a positive duration; zero, negative or malformed values fall
// back to the default (a non-positive interval would panic time.NewTicker).
func getdur(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// loadDotEnv is a tiny, dependency-free .env loader. It does not override
// variables already present in the environment.
func loadDotEnv(path string) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured .env path, not attacker-controlled
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.Trim(strings.TrimSpace(val), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
}
