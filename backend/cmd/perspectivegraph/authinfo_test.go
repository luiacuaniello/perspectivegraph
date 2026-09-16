package main

import (
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/config"
)

// GET /auth/config drives the dashboard's login gate, and its `authRequired` answers one
// question: will a call with no credential be rejected? Getting that wrong is not cosmetic
// in either direction - true on a published instance hides it behind a sign-in nobody can
// pass, false on a closed one shows a dashboard whose every request then fails.
func TestAuthRequiredTracksWhetherAnonymousIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cfg         config.Config
		authEnabled bool
		want        bool
		wantMode    string
	}{
		{"open instance", config.Config{}, false, false, "none"},
		{"tokens only", config.Config{APITokens: "t:admin"}, true, true, "token"},
		{"oidc only", config.Config{OIDCJWKSURL: "https://idp/keys"}, true, true, "oidc"},
		{
			// The published instance: credentials exist for its owner, and a visitor
			// still gets in without one.
			"tokens plus anonymous viewer",
			config.Config{APITokens: "t:admin", APIAnonymousRole: "viewer"},
			true, false, "token",
		},
		{
			"anonymous viewer alone",
			config.Config{APIAnonymousRole: "viewer"},
			true, false, "token",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := authInfoFromConfig(tc.cfg, tc.authEnabled)
			if info.Required != tc.want {
				t.Errorf("authRequired = %v, want %v", info.Required, tc.want)
			}
			if info.Mode != tc.wantMode {
				t.Errorf("mode = %q, want %q - it still describes the credential an owner would use", info.Mode, tc.wantMode)
			}
		})
	}
}
