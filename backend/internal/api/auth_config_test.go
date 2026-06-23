package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
}
