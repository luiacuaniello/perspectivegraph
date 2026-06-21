// Package config loads AegisGraph configuration from environment variables
// (12-factor style). A .env file, if present, is loaded first.
package config

import (
	"os"
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

	// Observability
	LogLevel string
}

// Load reads configuration from the environment, applying sane defaults so the
// stack runs against the bundled docker-compose with zero configuration.
func Load() Config {
	loadDotEnv(".env")

	return Config{
		PostgresDSN: getenv("POSTGRES_DSN", buildPostgresDSN()),
		AGEGraph:    getenv("AGE_GRAPH_NAME", "aegis"),

		NATSURL:     getenv("NATS_URL", "nats://localhost:4222"),
		NATSStream:  getenv("NATS_STREAM", "AEGIS"),
		NATSSubject: getenv("NATS_SUBJECT", "aegis.events.*"),

		APIAddr:    getenv("API_ADDR", ":8080"),
		IngestAddr: getenv("INGEST_ADDR", ":8081"),

		AnalyzerInterval: getdur("ANALYZER_INTERVAL", 30*time.Second),

		GitHubToken:  getenv("GITHUB_TOKEN", ""),
		GitHubAPIURL: getenv("GITHUB_API_URL", "https://api.github.com"),
		GitHubDryRun: getbool("GITHUB_DRY_RUN", false),

		GitLabToken:  getenv("GITLAB_TOKEN", ""),
		GitLabAPIURL: getenv("GITLAB_API_URL", "https://gitlab.com/api/v4"),
		GitLabDryRun: getbool("GITLAB_DRY_RUN", false),

		OpenSearchURL: getenv("OPENSEARCH_URL", ""),

		LogLevel: getenv("LOG_LEVEL", "info"),
	}
}

func buildPostgresDSN() string {
	host := getenv("POSTGRES_HOST", "localhost")
	port := getenv("POSTGRES_PORT", "5432")
	user := getenv("POSTGRES_USER", "aegis")
	pass := getenv("POSTGRES_PASSWORD", "aegis")
	db := getenv("POSTGRES_DB", "aegisgraph")
	return "host=" + host + " port=" + port + " user=" + user +
		" password=" + pass + " dbname=" + db + " sslmode=disable"
}

func getenv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
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

func getdur(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
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
