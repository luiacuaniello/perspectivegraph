package api

import (
	"encoding/json"
	"net/http"
)

// AuthInfo is the PUBLIC auth configuration the dashboard needs to render its
// login gate - what credential to ask for, and (when configured) where to start
// an SSO sign-in. It carries no secrets: only the IdP's public coordinates.
type AuthInfo struct {
	// Required is true when the API rejects anonymous calls (a credential is
	// needed). False means the API is open and the SPA skips the login gate.
	Required bool `json:"authRequired"`
	// Mode is one of none|token|oidc|both - what the login gate should offer.
	Mode string `json:"mode"`
	// OIDC is present only when single-sign-on is configured for login.
	OIDC *OIDCInfo `json:"oidc,omitempty"`
}

// OIDCInfo is the SPA-facing slice of the OIDC setup. issuer/audience identify
// the IdP; clientId/authorizeUrl/scopes are what the gate needs to start an
// Authorization-Code redirect. None of these are secret.
type OIDCInfo struct {
	Issuer       string `json:"issuer,omitempty"`
	Audience     string `json:"audience,omitempty"`
	ClientID     string `json:"clientId,omitempty"`
	AuthorizeURL string `json:"authorizeUrl,omitempty"`
	// TokenURL is the IdP token endpoint. When present the dashboard runs the full
	// Authorization-Code + PKCE flow (code → token exchange); when absent it falls
	// back to an implicit #access_token return.
	TokenURL string `json:"tokenUrl,omitempty"`
	Scopes   string `json:"scopes,omitempty"`
}

// WithAuthInfo sets the public auth configuration served at GET /auth/config.
// Returns the API for chaining.
func (a *API) WithAuthInfo(info AuthInfo) *API {
	a.authInfo = info
	return a
}

// handleAuthConfig serves the public auth configuration so the dashboard can
// render the right login gate without a rebuild. Open (no auth) by necessity -
// it's what tells an unauthenticated SPA how to authenticate - and secret-free.
func (a *API) handleAuthConfig(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(a.authInfo)
}
