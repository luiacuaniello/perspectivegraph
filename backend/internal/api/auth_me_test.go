package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
)

// GET /auth/me is how the dashboard decides which actions to offer, so the contract that
// matters is not the payload's shape but that it tells the truth: canWrite has to be what
// the server would actually do with a write from the same caller.

const meTokens = "view-tok:viewer,op-tok:operator,admin-tok:admin,globex-tok:viewer:globex,scoped-tok:viewer:default::payments|web"

func meOf(t *testing.T, a *API, bearer string) (int, map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := serve(t, a, r)
	if rec.Code != http.StatusOK {
		return rec.Code, nil, rec
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	return rec.Code, body, rec
}

func authenticatedAPI(t *testing.T) *API {
	t.Helper()
	return seededAPI(t).WithAuth(auth.NewTokenStore(meTokens), nil)
}

func TestAuthMeDescribesEachCredential(t *testing.T) {
	a := authenticatedAPI(t)
	for _, tc := range []struct {
		bearer, role, tenant string
		apps                 []any
		canWrite             bool
	}{
		{bearer: "view-tok", role: "viewer", tenant: "default"},
		// Operator reads like a viewer here: every write the API takes is admin-only.
		{bearer: "op-tok", role: "operator", tenant: "default"},
		{bearer: "admin-tok", role: "admin", tenant: "default", canWrite: true},
		{bearer: "globex-tok", role: "viewer", tenant: "globex"},
		{bearer: "scoped-tok", role: "viewer", tenant: "default", apps: []any{"payments", "web"}},
	} {
		t.Run(tc.bearer, func(t *testing.T) {
			code, me, rec := meOf(t, a, tc.bearer)
			if code != http.StatusOK {
				t.Fatalf("status %d: %s", code, rec.Body.String())
			}
			if me["role"] != tc.role || me["tenant"] != tc.tenant || me["canWrite"] != tc.canWrite || me["anonymous"] != false {
				t.Errorf("got %s, want role %s tenant %s canWrite %v, not anonymous", rec.Body.String(), tc.role, tc.tenant, tc.canWrite)
			}
			if !reflect.DeepEqual(me["apps"], func() any {
				if tc.apps == nil {
					return nil
				}
				return tc.apps
			}()) {
				t.Errorf("apps = %v, want %v", me["apps"], tc.apps)
			}
			// The subject is the audit log's pseudonym. The token itself must never come back.
			if sub, _ := me["subject"].(string); !strings.HasPrefix(sub, "token:") {
				t.Errorf("subject = %q, want the token fingerprint", sub)
			}
			if strings.Contains(rec.Body.String(), tc.bearer) {
				t.Errorf("the response echoes the bearer token: %s", rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("an identity answer must not be cached")
			}
		})
	}
}

// Behind the same door as the data: no credential and a wrong one both get 401, on a
// published instance too, where a wrong token must not fall back to anonymous.
func TestAuthMeRefusesWhatTheAPIRefuses(t *testing.T) {
	if code, _, _ := meOf(t, authenticatedAPI(t), ""); code != http.StatusUnauthorized {
		t.Errorf("no credential on an authenticated instance: status %d, want 401", code)
	}
	if code, _, _ := meOf(t, authenticatedAPI(t), "not-a-token"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: status %d, want 401", code)
	}
	if code, _, _ := meOf(t, publicReadOnly(t), "not-a-token"); code != http.StatusUnauthorized {
		t.Errorf("wrong token on a published instance: status %d, want 401", code)
	}
}

// The two callers without a credential. On an open instance there is no RBAC - no role to
// report, and writes are taken. On a published one the visitor is a viewer who cannot
// write, and "anonymous" is what lets the page say the instance is read-only rather than
// blame a role the visitor never chose.
func TestAuthMeWithoutACredential(t *testing.T) {
	code, open, rec := meOf(t, seededAPI(t), "")
	if code != http.StatusOK {
		t.Fatalf("open instance: status %d", code)
	}
	if _, hasRole := open["role"]; hasRole || open["anonymous"] != true || open["canWrite"] != true {
		t.Errorf("open instance = %s, want no role, anonymous, canWrite", rec.Body.String())
	}

	code, pub, rec := meOf(t, publicReadOnly(t), "")
	if code != http.StatusOK {
		t.Fatalf("published instance: status %d", code)
	}
	if pub["role"] != "viewer" || pub["anonymous"] != true || pub["canWrite"] != false || pub["subject"] != "anonymous" {
		t.Errorf("published instance = %s, want an anonymous viewer that cannot write", rec.Body.String())
	}

	// Its owner signing in is exactly how a published instance gets changed.
	code, owner, rec := meOf(t, publicReadOnly(t), "s3cr3t")
	if code != http.StatusOK || owner["canWrite"] != true || owner["anonymous"] != false {
		t.Errorf("admin on a published instance = %d %s, want canWrite and not anonymous", code, rec.Body.String())
	}
}

// The property the dashboard relies on. If these two ever disagree, the page either
// offers a button that fails or hides one that would have worked.
func TestAuthMeCanWriteMatchesTheServersAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		api    func(*testing.T) *API
		bearer string
	}{
		{"open", seededAPI, ""},
		{"viewer", authenticatedAPI, "view-tok"},
		{"operator", authenticatedAPI, "op-tok"},
		{"admin", authenticatedAPI, "admin-tok"},
		{"published visitor", publicReadOnly, ""},
		{"published owner", publicReadOnly, "s3cr3t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.api(t)
			_, me, rec := meOf(t, a, tc.bearer)
			if me == nil {
				t.Fatalf("/auth/me failed: %d %s", rec.Code, rec.Body.String())
			}
			w := httptest.NewRequest(http.MethodPost, "/suppressions", strings.NewReader(`{"pathId":"p1","reason":"accept-risk","owner":"x@y.z"}`))
			w.Header.Set("Content-Type", "application/json")
			if tc.bearer != "" {
				w.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			got := serve(t, a, w)
			refused := got.Code == http.StatusForbidden
			if me["canWrite"] == refused {
				t.Errorf("/auth/me says canWrite=%v, but the write answered %d: %s", me["canWrite"], got.Code, got.Body.String())
			}
		})
	}
}
