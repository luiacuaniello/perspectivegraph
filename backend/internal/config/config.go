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

	// HTTP servers
	APIAddr    string
	IngestAddr string

	// Analyzer
	AnalyzerInterval time.Duration
	AnalyzerMaxHops  int
	AnalyzerDBPaths  bool

	// GitHub PR commenter (action layer)
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

	// Auth (optional; open with a warning when unset)
	IngestHMACSecret  string // HMAC secret for the default tenant
	IngestHMACSecrets string // per-tenant secrets: "tenant:secret,tenant2:secret2"
	APITokens         string // bearer tokens → role[:tenant]: "tok:viewer,tok2:admin:globex"

	// OIDC/JWT (optional API auth alongside static tokens)
	OIDCJWKSURL  string
	OIDCIssuer   string
	OIDCAudience string

	// Audit (optional; tamper-evident hash-chained log file)
	AuditLogPath string

	// Triage/suppression store (optional; file-backed). When set, analyst
	// decisions to suppress a specific attack path (accept-risk / false-positive
	// / mitigating-control / duplicate, with owner + optional expiry) persist
	// here as JSON. Empty → in-memory only (lost on restart).
	SuppressionsPath string

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
	// the attack map never persists a live credential. On by default — disable only
	// with a deliberate reason. Retention of the (scrubbed) findings is handled by
	// GraphTTL; the graph is derived and re-seedable, so nothing sensitive needs to
	// live there long-term.
	ScrubIngest bool

	// CORS: browser origins allowed to call the API cross-origin. Defaults to the
	// local Vite dev server + the docker-compose dashboard. Set to "*" to allow any
	// origin (not recommended), or to your dashboard's real origin in production.
	CORSAllowedOrigins []string

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
	LogLevel string
}

// Load reads configuration from the environment, applying sane defaults so the
// stack runs against the bundled docker-compose with zero configuration.
func Load() Config {
	// The backend usually runs from backend/ (make run-backend), while the
	// shared .env lives at the repo root next to docker-compose: try both, so
	// one file configures everything. Real env vars always win.
	loadDotEnv(".env")
	loadDotEnv(filepath.Join("..", ".env"))

	return Config{
		PostgresDSN: getenv("POSTGRES_DSN", buildPostgresDSN()),
		AGEGraph:    getenv("AGE_GRAPH_NAME", "perspective"),

		NATSURL:     getenv("NATS_URL", "nats://localhost:4222"),
		NATSStream:  getenv("NATS_STREAM", "PERSPECTIVE"),
		NATSSubject: getenv("NATS_SUBJECT", "perspective.events.*"),

		APIAddr:    getenv("API_ADDR", ":8080"),
		IngestAddr: getenv("INGEST_ADDR", ":8081"),

		AnalyzerInterval: getdur("ANALYZER_INTERVAL", 30*time.Second),
		AnalyzerMaxHops:  getint("ANALYZER_MAX_HOPS", 12),
		AnalyzerDBPaths:  getbool("ANALYZER_DB_PATHS", false),

		GitHubToken:  getenv("GITHUB_TOKEN", ""),
		GitHubAPIURL: getenv("GITHUB_API_URL", "https://api.github.com"),
		GitHubDryRun: getbool("GITHUB_DRY_RUN", false),

		GitLabToken:  getenv("GITLAB_TOKEN", ""),
		GitLabAPIURL: getenv("GITLAB_API_URL", "https://gitlab.com/api/v4"),
		GitLabDryRun: getbool("GITLAB_DRY_RUN", false),

		OpenSearchURL: getenv("OPENSEARCH_URL", ""),

		ThreatIntelEnabled: getbool("THREATINTEL", false),
		KEVFeedURL:         getenv("KEV_FEED_URL", ""),
		EPSSAPIURL:         getenv("EPSS_API_URL", ""),

		IngestHMACSecret:  getenv("INGEST_HMAC_SECRET", ""),
		IngestHMACSecrets: getenv("INGEST_HMAC_SECRETS", ""),
		APITokens:         getenv("API_TOKENS", ""),

		OIDCJWKSURL:  getenv("OIDC_JWKS_URL", ""),
		OIDCIssuer:   getenv("OIDC_ISSUER", ""),
		OIDCAudience: getenv("OIDC_AUDIENCE", ""),

		AuditLogPath:     getenv("AUDIT_LOG_PATH", ""),
		SuppressionsPath: getenv("SUPPRESSIONS_PATH", ""),
		HistoryPath:      getenv("HISTORY_PATH", ""),
		TicketsPath:      getenv("TICKETS_PATH", ""),
		TicketWebhookURL: getenv("TICKET_WEBHOOK_URL", ""),
		ValidationsPath:  getenv("VALIDATIONS_PATH", ""),

		AlertWebhookURL:    getenv("ALERT_WEBHOOK_URL", ""),
		AlertWebhookFormat: getenv("ALERT_WEBHOOK_FORMAT", "slack"),

		IngestRateRPS: getfloat("INGEST_RATE_RPS", 30),
		APIRateRPS:    getfloat("API_RATE_RPS", 60),
		GraphStrict:   getbool("GRAPH_STRICT", false),
		GraphTTL:      getdur("GRAPH_TTL", 0),
		ScrubIngest:   getbool("SCRUB_INGEST", true),

		CORSAllowedOrigins: getlist("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000"),

		StoreEncryptionKey: getenv("STORE_ENCRYPTION_KEY", ""),
		ExportSigningKey:   getenv("EXPORT_SIGNING_KEY", ""),

		AuthLockoutThreshold: getint("AUTH_LOCKOUT_THRESHOLD", 50),
		ExfilAlertThreshold:  getint("EXFIL_ALERT_THRESHOLD", 0),

		LogLevel: getenv("LOG_LEVEL", "info"),
	}
}

func buildPostgresDSN() string {
	host := getenv("POSTGRES_HOST", "localhost")
	port := getenv("POSTGRES_PORT", "5432")
	user := getenv("POSTGRES_USER", "perspective")
	pass := getenv("POSTGRES_PASSWORD", "perspective")
	db := getenv("POSTGRES_DB", "perspectivegraph")
	return "host=" + host + " port=" + port + " user=" + user +
		" password=" + pass + " dbname=" + db + " sslmode=disable"
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
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
	data, err := os.ReadFile(path)
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
