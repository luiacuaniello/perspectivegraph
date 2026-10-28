package main

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/config"
)

// The engine keys a tenant by its normalized name, so two spellings of one name are one
// tenant: "acme-corp" and "acme.corp" would share a graph, and the second ingest secret
// replaced the first without a word. The process refuses that configuration instead.
func TestTwoSpellingsOfOneTenantRefuseToStart(t *testing.T) {
	for name, cfg := range map[string]config.Config{
		"an ingest secret and a token": {IngestHMACSecrets: "acme-corp:s1", APITokens: "tok:viewer:acme_corp"},
		"a token and the connectors":   {APITokens: "tok:viewer:acme_corp", ConnectorTenant: "Acme-Corp"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkTenantNames(cfg, auth.NewTokenStore(cfg.APITokens))
			if err == nil || !strings.Contains(err.Error(), "one tenant to the engine") {
				t.Errorf("want a refusal naming both spellings, got %v", err)
			}
		})
	}
	for name, cfg := range map[string]config.Config{
		"one tenant's name in two cases":          {IngestHMACSecrets: "Acme:s1,acme:s2"},
		"two names that normalize alike":          {IngestHMACSecrets: "acme-corp:s1,acme.corp:s2"},
		"the default tenant's secret given twice": {IngestHMACSecret: "s1", IngestHMACSecrets: "default:s2"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkTenantNames(cfg, auth.NewTokenStore(cfg.APITokens))
			if err == nil || !strings.Contains(err.Error(), "two ingest secrets") {
				t.Errorf("want a refusal of the second secret, got %v", err)
			}
		})
	}
	for name, cfg := range map[string]config.Config{
		"one spelling used everywhere": {IngestHMACSecrets: "acme:s1,globex:s2", APITokens: "a:viewer:acme,b:admin:globex",
			ConnectorTenant: "acme"},
		"nothing but the default": {IngestHMACSecret: "s", APITokens: "tok:admin"},
		"one name in two cases":   {IngestHMACSecrets: "Acme:s1", APITokens: "tok:viewer:acme"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkTenantNames(cfg, auth.NewTokenStore(cfg.APITokens)); err != nil {
				t.Errorf("a consistent configuration was refused: %v", err)
			}
		})
	}
}

// A token without a tenant claim is refused only where the configuration names a tenant
// besides the default: a single-tenant deployment keeps reading it as the default's.
func TestSeveralTenantsAreRecognisedFromTheConfiguration(t *testing.T) {
	for name, c := range map[string]struct {
		cfg  config.Config
		want bool
	}{
		"nothing configured":               {cfg: config.Config{}, want: false},
		"only the default tenant's secret": {cfg: config.Config{IngestHMACSecret: "s", APITokens: "tok:admin"}, want: false},
		"a token naming the default":       {cfg: config.Config{APITokens: "tok:admin:default"}, want: false},
		"a per-tenant ingest secret":       {cfg: config.Config{IngestHMACSecrets: "acme:s"}, want: true},
		"a token scoped to another tenant": {cfg: config.Config{APITokens: "tok:viewer:globex"}, want: true},
		"the connectors write to a tenant": {cfg: config.Config{ConnectorTenant: "acme"}, want: true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := servesSeveralTenants(c.cfg, auth.NewTokenStore(c.cfg.APITokens)); got != c.want {
				t.Errorf("servesSeveralTenants = %v, want %v", got, c.want)
			}
		})
	}
}
