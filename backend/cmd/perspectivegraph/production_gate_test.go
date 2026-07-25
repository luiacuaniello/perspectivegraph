package main

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/config"
)

// The production gate turns "API auth is disabled" from a warning into a refusal to
// start. It is worth testing precisely because it is a single boolean guarding the
// difference between a demo and an environment that publishes its own attack map:
// the failure mode of getting it wrong is silent, and looks exactly like success.

func TestIsProductionOnlyOptsInOnTheExactWord(t *testing.T) {
	for _, in := range []string{"production", "Production", "PRODUCTION", "  production  "} {
		if !isProduction(in) {
			t.Errorf("%q should opt into the production gate", in)
		}
	}

	// Everything else keeps the permissive demo behaviour. This direction is the one
	// that matters: a typo must never *enable* a stricter mode the operator did not
	// ask for, and must never be read as production when it isn't - the flag can only
	// ever add checks, so failing open here is failing safe.
	for _, in := range []string{"", "demo", "dev", "prod", "produciton", "staging", "PRODUCTION_LIKE"} {
		if isProduction(in) {
			t.Errorf("%q must not be treated as production", in)
		}
	}
}

// TestCheckProductionConfig exercises the real validator, not a restatement of its
// logic, so a later refactor cannot quietly invert it. It runs on configuration
// alone - no dependency has to be reachable - which is the point: a misconfiguration
// should fail on its own terms rather than hide behind whichever dependency happens
// to be down first.
func TestCheckProductionConfig(t *testing.T) {
	cases := []struct {
		name    string
		cfg     config.Config
		wantErr string // substring; empty means startup should proceed
	}{
		{
			name: "demo without credentials is the frictionless default",
			cfg:  config.Config{Env: "demo"},
		},
		{
			name: "an unset environment behaves like demo",
			cfg:  config.Config{},
		},
		{
			name:    "production without any API credential refuses to start",
			cfg:     config.Config{Env: "production", IngestHMACSecret: "s"},
			wantErr: "open GraphQL endpoint",
		},
		{
			name:    "production without ingest authentication refuses to start",
			cfg:     config.Config{Env: "production", APITokens: "tok:admin"},
			wantErr: "open ingest endpoints",
		},
		{
			name: "production with static tokens and an ingest secret proceeds",
			cfg:  config.Config{Env: "production", APITokens: "tok:admin", IngestHMACSecret: "s"},
		},
		{
			name: "SSO counts as an API credential",
			cfg:  config.Config{Env: "production", OIDCJWKSURL: "https://idp/jwks", IngestHMACSecrets: "t:s"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkProductionConfig(c.cfg)
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("expected startup to proceed, got: %v", err)
			case c.wantErr != "" && err == nil:
				t.Errorf("expected a refusal mentioning %q, got nil", c.wantErr)
			case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
				t.Errorf("error should mention %q, got: %v", c.wantErr, err)
			}
		})
	}
}

// The refusal has to tell the operator how to resolve it: an error that only says
// "no" costs a support round-trip at exactly the wrong moment.
func TestRefusalNamesTheFix(t *testing.T) {
	err := checkProductionConfig(config.Config{Env: "production"})
	if err == nil {
		t.Fatal("production without credentials must refuse")
	}
	for _, want := range []string{"API_TOKENS", "OIDC_JWKS_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should name %s as the fix, got: %v", want, err)
		}
	}
}
