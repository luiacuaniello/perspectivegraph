package api

import "testing"

// engine { version } is how the dashboard - and anyone without a shell in the pod - tells
// which release answers. It reports exactly what the binary was given, never a guess, and
// any role can ask: the dashboard asks it for a read-only viewer too.
func TestEngineVersionReportsWhatTheBinaryIs(t *testing.T) {
	for _, tc := range []struct {
		name string
		api  *API
		want string
	}{
		{"a published build", New(nil, nil, nil).WithVersion("v1.40.0"), "v1.40.0"},
		{"a local build", New(nil, nil, nil).WithVersion("3f2a91c"), "3f2a91c"},
		{"nothing stamped", New(nil, nil, nil), "dev"},
		{"an empty stamp keeps dev", New(nil, nil, nil).WithVersion(""), "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := query(t, tc.api, `{ engine { version } }`)
			engine, _ := data["engine"].(map[string]any)
			if got := engine["version"]; got != tc.want {
				t.Fatalf("engine.version = %v, want %q", got, tc.want)
			}
		})
	}
}
