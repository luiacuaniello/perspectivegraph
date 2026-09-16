package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
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
