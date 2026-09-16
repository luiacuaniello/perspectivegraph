package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthConfigEndpoint(t *testing.T) {
	a, _ := testAPI(t)
	a.WithAuthInfo(AuthInfo{
		Required: true, Mode: "both",
		OIDC: &OIDCInfo{Issuer: "https://idp.example", ClientID: "spa", AuthorizeURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token", Scopes: "openid"},
	})

	rec := httptest.NewRecorder()
	a.handleAuthConfig(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("auth config must not be cached")
	}
	var got AuthInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Required || got.Mode != "both" {
		t.Errorf("got Required=%v Mode=%q", got.Required, got.Mode)
	}
	if got.OIDC == nil || got.OIDC.ClientID != "spa" || got.OIDC.AuthorizeURL == "" || got.OIDC.TokenURL == "" {
		t.Errorf("OIDC info not exposed for the login gate (need clientId/authorizeUrl/tokenUrl for PKCE): %+v", got.OIDC)
	}
}

// TestAuthConfigOpenLeaksNothing: when auth is disabled the SPA skips the gate
// and no IdP details are served.
func TestAuthConfigOpenLeaksNothing(t *testing.T) {
	a, _ := testAPI(t)
	a.WithAuthInfo(AuthInfo{Required: false, Mode: "none"})

	rec := httptest.NewRecorder()
	a.handleAuthConfig(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))

	var got AuthInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Required || got.OIDC != nil {
		t.Errorf("open mode should require nothing and expose no OIDC: %+v", got)
	}
	// Absent, not empty: the dashboard reads a missing anonymousRole as "open by accident",
	// and an older dashboard must see the same payload it always did.
	if strings.Contains(rec.Body.String(), "anonymousRole") {
		t.Errorf("an open instance must not claim to be published on purpose: %s", rec.Body.String())
	}
}

// TestAuthConfigNamesTheAnonymousRole: a published read-only instance says so, which is
// what lets the dashboard show a quiet read-only notice instead of the open-instance alarm.
func TestAuthConfigNamesTheAnonymousRole(t *testing.T) {
	a, _ := testAPI(t)
	a.WithAuthInfo(AuthInfo{Required: false, Mode: "token", AnonymousRole: "viewer"})

	rec := httptest.NewRecorder()
	a.handleAuthConfig(rec, httptest.NewRequest(http.MethodGet, "/auth/config", nil))

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["authRequired"] != false || got["anonymousRole"] != "viewer" {
		t.Errorf("published instance payload = %s, want authRequired false and anonymousRole viewer", rec.Body.String())
	}
}
