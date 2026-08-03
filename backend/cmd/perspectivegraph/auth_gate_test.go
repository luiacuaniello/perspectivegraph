package main

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/config"
)

// checkAuthConfig closes the confused-deputy hole: a JWT verifier without issuer and
// audience validation accepts any token its IdP ever minted, including one issued to a
// different relying party sharing the same JWKS - so another application's user silently
// becomes this application's user, with whatever role and tenant claims they carry.
//
// It is tested here for the same reason the production gate is: it is one boolean
// standing between "SSO" and "anyone with a token from the corporate IdP", and getting
// it wrong looks exactly like it working.

func TestAuthGateRefusesOIDCWithoutIssuerOrAudience(t *testing.T) {
	cases := []struct {
		name            string
		jwks, iss, aud  string
		wantRefusal     bool
		refusalMentions string
	}{
		{
			name: "both missing", jwks: "https://idp/jwks", iss: "", aud: "",
			wantRefusal: true, refusalMentions: "OIDC_ISSUER",
		},
		{
			name: "issuer missing", jwks: "https://idp/jwks", iss: "", aud: "perspectivegraph",
			wantRefusal: true, refusalMentions: "OIDC_ISSUER",
		},
		{
			name: "audience missing", jwks: "https://idp/jwks", iss: "https://idp/", aud: "",
			wantRefusal: true, refusalMentions: "OIDC_AUDIENCE",
		},
		{
			name: "both present", jwks: "https://idp/jwks", iss: "https://idp/", aud: "perspectivegraph",
			wantRefusal: false,
		},
		{
			// No OIDC at all is the static-token deployment; iss/aud are meaningless
			// there and must not be demanded.
			name: "oidc disabled", jwks: "", iss: "", aud: "",
			wantRefusal: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkAuthConfig(config.Config{
				OIDCJWKSURL:  c.jwks,
				OIDCIssuer:   c.iss,
				OIDCAudience: c.aud,
			})
			if c.wantRefusal && err == nil {
				t.Fatal("started with a JWT verifier that skips iss/aud")
			}
			if !c.wantRefusal && err != nil {
				t.Fatalf("refused a valid configuration: %v", err)
			}
			if c.wantRefusal && !strings.Contains(err.Error(), c.refusalMentions) {
				t.Errorf("the refusal does not name %s, so nobody can act on it: %v", c.refusalMentions, err)
			}
		})
	}
}

// The rule is NOT production-only. A staging deployment wired to the corporate IdP has
// exactly the same hole, so the refusal must not depend on PG_ENV - which is precisely
// why this lives outside checkProductionConfig.
func TestAuthGateAppliesOutsideProduction(t *testing.T) {
	for _, env := range []string{"", "development", "demo", "staging"} {
		cfg := config.Config{Env: env, OIDCJWKSURL: "https://idp/jwks"}
		if err := checkAuthConfig(cfg); err == nil {
			t.Errorf("PG_ENV=%q: OIDC without iss/aud was accepted outside production", env)
		}
		// And the production gate must not be the thing enforcing it, or moving the
		// check would silently narrow it to production again.
		if err := checkProductionConfig(cfg); err != nil && strings.Contains(err.Error(), "OIDC_AUDIENCE") {
			t.Errorf("PG_ENV=%q: the iss/aud rule leaked into the production-only gate", env)
		}
	}
}

// A refusal nobody can act on is a refusal that gets deleted. It has to name both the
// variable to set and the way out.
func TestAuthRefusalNamesTheFix(t *testing.T) {
	err := checkAuthConfig(config.Config{OIDCJWKSURL: "https://idp/jwks"})
	if err == nil {
		t.Fatal("no refusal")
	}
	for _, want := range []string{"OIDC_ISSUER", "OIDC_AUDIENCE", "API_TOKENS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal never mentions %s: %v", want, err)
		}
	}
}
