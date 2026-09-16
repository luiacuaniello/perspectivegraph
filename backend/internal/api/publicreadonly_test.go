package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/clientip"
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
)

// A published instance - the public demo, or a dashboard a whole company may read - is the
// one deployment where an unauthenticated request is meant to get an answer. This is the
// whole contract of that mode, exercised through the real handler chain rather than by
// injecting a principal: reads answer, every write is refused BY THE SERVER, and a bad
// credential is still a bad credential.
func publicReadOnly(t *testing.T) *API {
	t.Helper()
	anon, err := auth.NewAnonymous(auth.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	a := seededAPI(t)
	return a.WithAuth(auth.Chain{auth.NewTokenStore("s3cr3t:admin"), anon}, nil)
}

func TestAPublishedInstanceAnswersReadsWithoutACredential(t *testing.T) {
	a := publicReadOnly(t)
	for _, target := range []string{"/graphql", "/suppressions", "/validations", "/tickets"} {
		t.Run(target, func(t *testing.T) {
			var r *http.Request
			if target == "/graphql" {
				r = httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"query":"{ attackPaths(limit: 1) { id } }"}`))
				r.Header.Set("Content-Type", "application/json")
			} else {
				r = httptest.NewRequest(http.MethodGet, target, nil)
			}
			if rec := serve(t, a, r); rec.Code != http.StatusOK {
				t.Fatalf("status %d for an anonymous read: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// The reason this is safe to publish. Every one of these is a change to what the product
// reports - hiding a path, recording an outcome, opening a pull request - and none may be
// made by someone who only found the URL.
func TestAPublishedInstanceRefusesEveryWrite(t *testing.T) {
	a := publicReadOnly(t)
	for _, tc := range []struct{ name, method, target, body string }{
		{"suppress a path", http.MethodPost, "/suppressions", `{"pathId":"p1","reason":"accept-risk","owner":"x@y.z"}`},
		{"un-suppress a path", http.MethodDelete, "/suppressions/p1", ""},
		{"record a verdict", http.MethodPost, "/validations", `{"pathId":"p1","outcome":"refuted","source":"anyone"}`},
		{"import verdicts", http.MethodPost, "/validations/import", `{"findings":[]}`},
		{"delete a verdict", http.MethodDelete, "/validations/v1", ""},
		{"open a ticket", http.MethodPost, "/tickets", `{"pathId":"p1","owner":"x@y.z"}`},
		{"close a ticket", http.MethodPost, "/tickets/t1/close", ""},
		{"open a remediation PR", http.MethodPost, "/remediation/pr", `{"pathId":"p1"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r *http.Request
			if tc.body == "" {
				r = httptest.NewRequest(tc.method, tc.target, nil)
			} else {
				r = httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
				r.Header.Set("Content-Type", "application/json")
			}
			rec := serve(t, a, r)
			// 403 is the answer this mode owes: the request was understood, the role was
			// not enough. A 2xx would mean the public could change what the product says.
			if rec.Code < 400 {
				t.Fatalf("status %d - an anonymous caller performed a write: %s", rec.Code, rec.Body.String())
			}
			if rec.Code != http.StatusForbidden && rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status %d, want 403 (or 503 when the feature is not configured at all): %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// Anonymous read must not blunt authentication: a wrong token is still rejected, and the
// admin token still works.
func TestAPublishedInstanceStillHonoursCredentials(t *testing.T) {
	a := publicReadOnly(t)

	bad := httptest.NewRequest(http.MethodGet, "/suppressions", nil)
	bad.Header.Set("Authorization", "Bearer not-the-token")
	if rec := serve(t, a, bad); rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d for a wrong token, want 401 - it must not fall through to anonymous read", rec.Code)
	}

	admin := httptest.NewRequest(http.MethodPost, "/suppressions", strings.NewReader(`{"pathId":"p1","reason":"accept-risk","owner":"x@y.z"}`))
	admin.Header.Set("Content-Type", "application/json")
	admin.Header.Set("Authorization", "Bearer s3cr3t")
	if rec := serve(t, a, admin); rec.Code >= 400 {
		t.Errorf("status %d for the admin token: %s", rec.Code, rec.Body.String())
	}
}

// A published instance is reached through a proxy, always: in the compose recipe every
// visitor comes through the dashboard's nginx, so the connecting peer is nginx for all of
// them. Keyed on that peer the per-IP controls are global, and one person's wrong tokens
// lock every visitor out. Reproduced on a real stack before the recipe trusted its proxy:
// fifty bad tokens from one address, and a different visitor's read answered 429.
//
// The attacker here also writes the visitor's address into X-Forwarded-For, the other
// way to aim a lockout at someone else. Only the hops the trusted proxies appended count.
func TestAPublishedInstanceKeepsVisitorsApartBehindItsProxy(t *testing.T) {
	const (
		nginx    = "172.18.0.5:41234" // the dashboard container, on the compose network
		hostHop  = "172.18.0.1"       // appended by nginx: the TLS proxy on the host, via Docker
		attacker = "203.0.113.9"
		visitor  = "198.51.100.7"
	)
	through := func(r *http.Request, forwarded string) *http.Request {
		r.RemoteAddr = nginx
		r.Header.Set("X-Forwarded-For", forwarded)
		return r
	}
	read := func(from string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ attackPaths(limit: 1) { id } }"}`))
		r.Header.Set("Content-Type", "application/json")
		return through(r, from+", "+hostHop)
	}

	run := func(t *testing.T, trusted []string) (attackerRead, visitorRead int) {
		t.Helper()
		ips, err := clientip.New(trusted)
		if err != nil {
			t.Fatal(err)
		}
		guard := secwatch.New(3, time.Minute, time.Minute, nil)
		a := publicReadOnly(t).WithAbuseWatchers(nil, guard).WithClientIP(ips)
		for range 3 {
			guess := through(httptest.NewRequest(http.MethodGet, "/suppressions", nil), visitor+", "+attacker+", "+hostHop)
			guess.Header.Set("Authorization", "Bearer guess")
			serve(t, a, guess)
		}
		return serve(t, a, read(attacker)).Code, serve(t, a, read(visitor)).Code
	}

	t.Run("trusting the proxy, as the recipe does", func(t *testing.T) {
		attackerRead, visitorRead := run(t, []string{"172.16.0.0/12"})
		if attackerRead != http.StatusTooManyRequests {
			t.Errorf("attacker read = %d, want 429: the lockout must still stop the one who guessed", attackerRead)
		}
		if visitorRead != http.StatusOK {
			t.Errorf("visitor read = %d, want 200: someone else's guesses locked this visitor out", visitorRead)
		}
	})

	// The failure the recipe exists to prevent, pinned so the test above is not vacuous.
	t.Run("without it, one key for everybody", func(t *testing.T) {
		if _, visitorRead := run(t, nil); visitorRead != http.StatusTooManyRequests {
			t.Errorf("visitor read = %d, want 429 - if this no longer fails, the proxy default may be unnecessary", visitorRead)
		}
	})
}
