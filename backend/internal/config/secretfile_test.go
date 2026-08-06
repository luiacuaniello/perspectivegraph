package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSecret(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The point of <KEY>_FILE: the credential never has to appear in the environment, where
// /proc/<pid>/environ, `docker inspect` and every child process can see it.
func TestSecretIsReadFromFile(t *testing.T) {
	p := writeSecret(t, "hmac", "super-secret-value")
	t.Setenv("INGEST_HMAC_SECRET_FILE", p)

	sec := &secretReader{}
	if got := sec.get("INGEST_HMAC_SECRET", ""); got != "super-secret-value" {
		t.Fatalf("read %q from the file", got)
	}
	if len(sec.errs) != 0 {
		t.Errorf("unexpected errors: %v", sec.errs)
	}
}

// Secret files almost always end with a newline - `echo`, most secret managers, and
// `kubectl create secret --from-file` all add one. An HMAC key with a stray \n silently
// fails every signature check, which is a miserable thing to debug.
func TestTrailingNewlineIsStripped(t *testing.T) {
	for name, content := range map[string]string{
		"unix newline":    "value\n",
		"windows newline": "value\r\n",
		"several":         "value\n\n",
		"none":            "value",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("API_TOKENS_FILE", writeSecret(t, "tok", content))
			sec := &secretReader{}
			if got := sec.get("API_TOKENS", ""); got != "value" {
				t.Fatalf("got %q, want %q", got, "value")
			}
		})
	}
}

// Deliberately NOT TrimSpace: a passphrase may legitimately begin or end with a space,
// and silently altering a credential is worse than carrying a stray byte.
func TestInteriorAndLeadingWhitespaceSurvives(t *testing.T) {
	t.Setenv("STORE_ENCRYPTION_KEY_FILE", writeSecret(t, "k", " pass phrase with spaces \n"))
	sec := &secretReader{}
	if got := sec.get("STORE_ENCRYPTION_KEY", ""); got != " pass phrase with spaces " {
		t.Fatalf("the credential was altered: %q", got)
	}
}

// The dangerous case, and the reason this is a startup failure rather than a fallback.
// An operator who mounts a secret and mistypes the path has, to the process, simply not
// set that credential - and "no HMAC key" is not an error, it is the demo profile. So the
// mistake would start cleanly and serve an open endpoint: exactly what mounting a secret
// was meant to prevent.
func TestUnreadableFileIsAnErrorNotAFallback(t *testing.T) {
	t.Setenv("INGEST_HMAC_SECRET", "value-from-the-environment")
	t.Setenv("INGEST_HMAC_SECRET_FILE", "/does/not/exist")

	sec := &secretReader{}
	got := sec.get("INGEST_HMAC_SECRET", "a-default")

	if got == "value-from-the-environment" {
		t.Error("fell back to the environment after the named file failed")
	}
	if got == "a-default" {
		t.Error("fell back to the default after the named file failed")
	}
	if len(sec.errs) != 1 {
		t.Fatalf("errors = %v, want exactly one", sec.errs)
	}
	if !strings.Contains(sec.errs[0], "INGEST_HMAC_SECRET_FILE") || !strings.Contains(sec.errs[0], "/does/not/exist") {
		t.Errorf("the error names neither the variable nor the path: %q", sec.errs[0])
	}
}

// An empty file is the same mistake wearing different clothes: the mount happened but
// the secret never landed in it.
func TestEmptyFileIsAnError(t *testing.T) {
	t.Setenv("API_TOKENS_FILE", writeSecret(t, "empty", ""))
	sec := &secretReader{}
	if got := sec.get("API_TOKENS", ""); got != "" {
		t.Errorf("got %q from an empty file", got)
	}
	if len(sec.errs) != 1 || !strings.Contains(sec.errs[0], "empty") {
		t.Fatalf("errors = %v, want one mentioning the file is empty", sec.errs)
	}
}

// Nothing changes for anyone not using files: the environment still wins over the
// default, and an unset variable still yields the default.
func TestEnvironmentStillWorksWhenNoFileIsNamed(t *testing.T) {
	sec := &secretReader{}
	t.Setenv("GITHUB_TOKEN", "ghp_from_env")
	if got := sec.get("GITHUB_TOKEN", "def"); got != "ghp_from_env" {
		t.Errorf("got %q, want the environment value", got)
	}
	if got := sec.get("GITLAB_TOKEN", "def"); got != "def" {
		t.Errorf("got %q, want the default", got)
	}
	if len(sec.errs) != 0 {
		t.Errorf("unexpected errors: %v", sec.errs)
	}
}

// End to end through Load, including the Postgres password, which reaches the DSN by a
// different route than the rest.
func TestLoadReadsSecretsFromFiles(t *testing.T) {
	t.Setenv("POSTGRES_PASSWORD_FILE", writeSecret(t, "pg", "pg-secret\n"))
	t.Setenv("API_TOKENS_FILE", writeSecret(t, "api", "tok:admin\n"))
	t.Setenv("POSTGRES_DSN", "") // force the DSN to be built from parts

	cfg := Load()
	if len(cfg.SecretErrors) != 0 {
		t.Fatalf("SecretErrors = %v", cfg.SecretErrors)
	}
	if cfg.APITokens != "tok:admin" {
		t.Errorf("APITokens = %q", cfg.APITokens)
	}
	if !strings.Contains(cfg.PostgresDSN, "password=pg-secret") {
		t.Errorf("the password did not reach the DSN: %q", cfg.PostgresDSN)
	}
	if strings.Contains(cfg.PostgresDSN, "password=pg-secret\n") {
		t.Error("the DSN carries the file's trailing newline")
	}
}

// A bad path anywhere must surface on the Config, so the startup gate can refuse.
func TestLoadCollectsSecretErrors(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY_FILE", "/nope")
	cfg := Load()
	if len(cfg.SecretErrors) == 0 {
		t.Fatal("Load reported no error for an unreadable secret file")
	}
	if !strings.Contains(strings.Join(cfg.SecretErrors, " "), "ANTHROPIC_API_KEY_FILE") {
		t.Errorf("SecretErrors does not name the variable: %v", cfg.SecretErrors)
	}
}

// METRICS_ADDR moves Prometheus /metrics onto its own listener. This asserts the value
// actually reaches the field, which is not the same as the key appearing in the source.
//
// It is here because that is precisely the bug that happened: the edit adding the key to
// Load silently did not apply (gofmt had aligned the anchor line differently), so
// MetricsAddr stayed empty forever and the listener never started - and it compiled
// without a warning. The parity test caught it by scanning the source text, which would
// NOT have caught the value landing in the wrong field. This would.
func TestMetricsAddrReachesTheConfig(t *testing.T) {
	t.Setenv("METRICS_ADDR", "127.0.0.1:9090")
	if got := Load().MetricsAddr; got != "127.0.0.1:9090" {
		t.Fatalf("MetricsAddr = %q, want the value from the environment", got)
	}
}

// Empty is the default and it means "serve /metrics on the API port", which is the
// historical behaviour and declared stable surface. A non-empty default would silently
// relocate the endpoint for every existing deployment.
func TestMetricsAddrDefaultsToEmpty(t *testing.T) {
	t.Setenv("METRICS_ADDR", "")
	if got := Load().MetricsAddr; got != "" {
		t.Fatalf("MetricsAddr = %q with the variable unset, want empty", got)
	}
}
