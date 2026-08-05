package main

import (
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
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

// A mounted secret that cannot be read must stop the process, not degrade it. Without
// this gate the failure mode is silent and inverted: the operator who took the trouble
// to mount a secret gets the open deployment, while the one who pasted it into the
// environment gets the closed one.
func TestSecretGateRefusesAnUnreadableSecretFile(t *testing.T) {
	err := checkSecretConfig(config.Config{
		SecretErrors: []string{"INGEST_HMAC_SECRET_FILE is set to /run/secrets/hmac but it cannot be read: no such file"},
	})
	if err == nil {
		t.Fatal("started with a secret file that could not be read")
	}
	for _, want := range []string{"INGEST_HMAC_SECRET_FILE", "/run/secrets/hmac", "permissions"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal never mentions %q: %v", want, err)
		}
	}
}

func TestSecretGatePassesWhenNothingFailed(t *testing.T) {
	if err := checkSecretConfig(config.Config{}); err != nil {
		t.Fatalf("refused a configuration with no secret errors: %v", err)
	}
}

// Several bad paths must all be reported: fixing them one restart at a time is the kind
// of thing that makes an operator give up and paste the secret into the environment.
func TestSecretGateReportsEveryFailure(t *testing.T) {
	err := checkSecretConfig(config.Config{SecretErrors: []string{
		"API_TOKENS_FILE is set to /a but it cannot be read: x",
		"GITHUB_TOKEN_FILE is set to /b but the file is empty",
	}})
	if err == nil {
		t.Fatal("no refusal")
	}
	if !strings.Contains(err.Error(), "API_TOKENS_FILE") || !strings.Contains(err.Error(), "GITHUB_TOKEN_FILE") {
		t.Errorf("only some failures were reported: %v", err)
	}
}

// Found by actually running the stack: with PG_ENV=production and API_TOKENS set to a
// value the token parser rejects, the backend started and served the GraphQL endpoint
// with "API auth DISABLED" in the log. The gate only checked that the string was
// non-empty, so a missing ":admin" was enough to publish the attack map.
func TestProductionGateRejectsUnusableAPITokens(t *testing.T) {
	unusable := map[string]string{
		"no role at all":  "just-a-token",
		"unknown role":    "tok:wizard",
		"empty token":     ":admin",
		"only separators": ",,,",
	}
	for name, spec := range unusable {
		t.Run(name, func(t *testing.T) {
			err := checkProductionConfig(config.Config{
				Env: "production", APITokens: spec, IngestHMACSecret: "x",
			})
			if err == nil {
				t.Fatalf("production started with API_TOKENS=%q, which yields no usable credential", spec)
			}
			if !strings.Contains(err.Error(), "API_TOKENS") {
				t.Errorf("the refusal does not name API_TOKENS: %v", err)
			}
		})
	}
}

// ...and a well-formed one still starts, or the gate would just be a wall.
func TestProductionGateAcceptsUsableAPITokens(t *testing.T) {
	for name, spec := range map[string]string{
		"token and role":  "s3cr3t:admin",
		"with tenant":     "s3cr3t:viewer:acme",
		"future expiry":   "s3cr3t:admin:default:2999-01-01",
		"one of two good": "broken,s3cr3t:admin",
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkProductionConfig(config.Config{
				Env: "production", APITokens: spec, IngestHMACSecret: "x",
			}); err != nil {
				t.Fatalf("refused a usable API_TOKENS=%q: %v", spec, err)
			}
		})
	}
}

// SSO deployments configure no static tokens at all; the new check must not demand them.
func TestProductionGateAcceptsSSOWithoutStaticTokens(t *testing.T) {
	if err := checkProductionConfig(config.Config{
		Env: "production", OIDCJWKSURL: "https://idp/jwks", IngestHMACSecret: "x",
	}); err != nil {
		t.Fatalf("refused an SSO-only production configuration: %v", err)
	}
}

// An API_TOKENS whose entries are all EXPIRED is deliberately not rejected here, and it
// is worth saying why: an expired entry still parses, so the token store stays enabled
// and the middleware still runs - the expired token is refused at request time with a
// 401. That deployment is unusable, but it is unusable CLOSED, which is the safe half of
// the distinction this gate is about. Only credentials that vanish during parsing leave
// the endpoint open, and those are what it refuses.
func TestExpiredTokensFailClosedRatherThanOpen(t *testing.T) {
	cfg := config.Config{Env: "production", APITokens: "tok:admin:default:2020-01-01", IngestHMACSecret: "x"}
	if err := checkProductionConfig(cfg); err != nil {
		t.Fatalf("refused an all-expired API_TOKENS, which fails closed and is safe: %v", err)
	}
	if n := auth.NewTokenStore(cfg.APITokens).Len(); n == 0 {
		t.Fatal("an expired entry did not survive parsing - auth would be disabled, not merely locked")
	}
}

// The in-memory fallback is the right default for `make demo` and the wrong one for a
// declared production deployment: an unreachable database leaves the engine computing
// over an empty, volatile graph, and an empty graph answers "no attack paths" - which
// reads as good news. Observed live: a wrong Postgres password produced exactly that,
// with a healthy /healthz and a single warning in the log.
func TestDegradedReasonOnlyFlagsTheFallback(t *testing.T) {
	// A declared (non-demo) environment asked for a database and did not get one.
	if got := degradedReason(backendMemoryDegraded, "staging"); got == "" {
		t.Error("a store that fell back to memory in a declared environment is not reported as degraded")
	} else if !strings.Contains(got, "no attack paths") {
		t.Errorf("the reason does not say why it matters: %q", got)
	}

	// The demo profile - and an unset PG_ENV - is the zero-dependency local path
	// (`make run-backend`, no database at all). It takes the same fallback branch, so
	// flagging it would make local development report unhealthy and stop the dashboard
	// container, which waits on the backend being healthy.
	for _, env := range []string{"", "demo", "DEMO", "  demo  "} {
		if got := degradedReason(backendMemoryDegraded, env); got != "" {
			t.Errorf("PG_ENV=%q was reported degraded, breaking the zero-dependency path: %q", env, got)
		}
	}

	// A working store is never degraded, whatever the environment.
	for _, backend := range []string{"apache-age", "memory", ""} {
		if got := degradedReason(backend, "staging"); got != "" {
			t.Errorf("backend %q was reported degraded: %q", backend, got)
		}
	}
}
