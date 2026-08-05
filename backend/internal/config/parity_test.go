package config

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// A configuration key is only real if an operator can actually set it on the deployment
// they run. This test holds the three deploy surfaces to the one source of truth - the
// keys config.go reads - because the failure when they drift apart is silent and
// expensive: the operator follows OPERATIONS.md, puts the value in .env or values.yaml,
// and the process never sees it.
//
// It was written after finding exactly that. CORS_ALLOWED_ORIGINS and
// AUTH_LOCKOUT_THRESHOLD are prescribed for production by the runbook, and neither was
// passed through by docker-compose: an operator who restricted CORS got no CORS
// restriction, and nothing anywhere said so. Eighteen keys were missing from Compose and
// sixteen from Helm.

var keyRe = regexp.MustCompile(`(?:getenv|sec\.get|getbool|getint|getfloat|getdur|getlist)\("([A-Z0-9_]+)"`)

// exempt lists keys that legitimately do not need to appear on every surface, with the
// reason. Anything not listed here must be reachable from all three.
var exempt = map[string]string{
	"HUGGINGFACE_API_KEY": "accepted only as an alias for HF_TOKEN, which is exposed",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// internal/config -> backend -> repo root
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func mustRead(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatalf("reading %v: %v", parts, err)
	}
	return string(b)
}

// keysReadByTheBackend is the source of truth: what config.go actually looks up.
func keysReadByTheBackend(t *testing.T) []string {
	t.Helper()
	src := mustRead(t, "config.go")
	seen := map[string]bool{}
	for _, m := range keyRe.FindAllStringSubmatch(src, -1) {
		if _, skip := exempt[m[1]]; !skip {
			seen[m[1]] = true
		}
	}
	if len(seen) < 50 {
		t.Fatalf("only found %d keys in config.go - the extraction regex has drifted from the code", len(seen))
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestDeploySurfacesExposeEveryConfigKey(t *testing.T) {
	root := repoRoot(t)
	keys := keysReadByTheBackend(t)

	helm := mustRead(t, root, "deploy", "helm", "perspectivegraph", "templates", "config.yaml") +
		mustRead(t, root, "deploy", "helm", "perspectivegraph", "templates", "backend.yaml")

	surfaces := map[string]string{
		".env.example":       mustRead(t, root, ".env.example"),
		"docker-compose.yml": mustRead(t, root, "docker-compose.yml"),
		"deploy/helm":        helm,
	}

	for name, content := range surfaces {
		content = stripComments(content)
		var missing []string
		for _, k := range keys {
			// The key must appear as a DECLARATION - `KEY=`, `KEY:` or `name: KEY` -
			// not merely be mentioned. A first version of this test used a substring
			// match and was satisfied by the key appearing in a comment, which meant
			// it would have missed the very drift it exists to catch: deleting the
			// real passthrough left the comment behind, and the test stayed green.
			declared := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(k) + `\s*[:=]|name:\s*` + regexp.QuoteMeta(k) + `\b`)
			if !declared.MatchString(content) {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s does not expose %d key(s) the backend reads, so setting them there does nothing:\n  %s",
				name, len(missing), strings.Join(missing, "\n  "))
		}
	}
}

// The reverse drift: a surface advertising a key the backend stopped reading. Harmless at
// runtime, but it is a promise the software no longer keeps, and an operator will spend an
// afternoon wondering why it has no effect.
func TestEnvExampleDoesNotAdvertiseDeadKeys(t *testing.T) {
	root := repoRoot(t)
	live := map[string]bool{}
	for _, k := range keysReadByTheBackend(t) {
		live[k] = true
	}
	for k := range exempt {
		live[k] = true
	}
	// Keys consumed by compose itself or by other images, not by our backend.
	for _, k := range []string{
		"POSTGRES_USER", "POSTGRES_DB", "POSTGRES_HOST", "POSTGRES_PORT", // read via buildPostgresDSN's helpers
		"COMPOSE_PROJECT_NAME", "DOCKER_BUILDKIT",
	} {
		live[k] = true
	}

	var dead []string
	for _, m := range regexp.MustCompile(`(?m)^([A-Z0-9_]+)=`).FindAllStringSubmatch(mustRead(t, root, ".env.example"), -1) {
		k := m[1]
		if !live[k] && !strings.HasSuffix(k, "_FILE") {
			dead = append(dead, k)
		}
	}
	if len(dead) > 0 {
		sort.Strings(dead)
		t.Errorf(".env.example documents %d key(s) the backend no longer reads:\n  %s",
			len(dead), strings.Join(dead, "\n  "))
	}
}

// Every secret must be reachable through <KEY>_FILE, or the Docker and Kubernetes paths
// that avoid putting credentials in the environment cannot cover it.
func TestEverySecretAcceptsAFileVariant(t *testing.T) {
	secrets := []string{
		"POSTGRES_PASSWORD", "API_TOKENS", "INGEST_HMAC_SECRET", "INGEST_HMAC_SECRETS",
		"STORE_ENCRYPTION_KEY", "EXPORT_SIGNING_KEY", "GITHUB_TOKEN", "GITLAB_TOKEN",
		"ANTHROPIC_API_KEY", "HF_TOKEN", "TICKET_WEBHOOK_URL", "ALERT_WEBHOOK_URL",
	}
	src := mustRead(t, "config.go")
	for _, k := range secrets {
		if !strings.Contains(src, `sec.get("`+k+`"`) {
			t.Errorf("%s is a credential but is read with getenv, so %s_FILE does not work "+
				"and it cannot be supplied as a mounted secret", k, k)
		}
	}
}

// stripComments removes whole-line comments so a key named in prose cannot pass for a
// key an operator can actually set.
func stripComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
