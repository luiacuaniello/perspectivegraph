package config

import (
	"strings"
	"testing"
	"time"
)

// TestPostgresDSNSSLMode pins that the DB sslmode is configurable (and no longer
// hardcoded to "disable"): the default stays "disable" for the bundled demo DB,
// but POSTGRES_SSLMODE flows into the DSN so a managed/external instance can be
// required to use TLS.
func TestPostgresDSNSSLMode(t *testing.T) {
	cases := map[string]string{
		"":            "sslmode=disable",     // unset → safe demo default
		"disable":     "sslmode=disable",     // explicit
		"require":     "sslmode=require",     // encrypt
		"verify-full": "sslmode=verify-full", // encrypt + verify cert
	}
	for val, want := range cases {
		t.Setenv("POSTGRES_SSLMODE", val)
		if dsn := buildPostgresDSN(); !strings.Contains(dsn, want) {
			t.Errorf("POSTGRES_SSLMODE=%q → DSN %q, want it to contain %q", val, dsn, want)
		}
	}
}

// TestTLSConfigLoads checks the in-app TLS cert/key wiring (HTTP servers + NATS)
// is read from the env, so TLS/mTLS can be turned on without code changes.
func TestTLSConfigLoads(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "/etc/tls/tls.crt")
	t.Setenv("TLS_KEY_FILE", "/etc/tls/tls.key")
	t.Setenv("NATS_TLS_CA", "/etc/nats/ca.crt")
	t.Setenv("NATS_TLS_CERT", "/etc/nats/tls.crt")
	t.Setenv("NATS_TLS_KEY", "/etc/nats/tls.key")
	cfg := Load()
	if cfg.TLSCertFile != "/etc/tls/tls.crt" || cfg.TLSKeyFile != "/etc/tls/tls.key" {
		t.Errorf("HTTP TLS cert/key = %q/%q, want the configured paths", cfg.TLSCertFile, cfg.TLSKeyFile)
	}
	if cfg.NATSTLSCAFile != "/etc/nats/ca.crt" || cfg.NATSTLSCertFile != "/etc/nats/tls.crt" || cfg.NATSTLSKeyFile != "/etc/nats/tls.key" {
		t.Errorf("NATS TLS ca/cert/key = %q/%q/%q, want the configured paths", cfg.NATSTLSCAFile, cfg.NATSTLSCertFile, cfg.NATSTLSKeyFile)
	}
}

func TestGetdurRejectsNonPositiveAndMalformed(t *testing.T) {
	const def = 30 * time.Second
	cases := map[string]time.Duration{
		"10s":    10 * time.Second, // valid value wins
		"0s":     def,              // zero would panic time.NewTicker
		"-5s":    def,              // negative likewise
		"banana": def,              // malformed
		"":       def,              // empty → default
		"1m30s":  90 * time.Second, // composite durations parse
	}
	for val, want := range cases {
		t.Setenv("TEST_INTERVAL", val)
		if got := getdur("TEST_INTERVAL", def); got != want {
			t.Errorf("getdur(%q) = %v, want %v", val, got, want)
		}
	}
}
