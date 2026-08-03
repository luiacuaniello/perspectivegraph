package analyzer

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The output of shortID is embedded in the id: and tags: of generated Sigma and Falco
// rules, so an invalid or mangled fragment ships a detection file the user deploys.
func TestShortIDNeverProducesInvalidUTF8(t *testing.T) {
	cases := []string{
		"payments-admin",
		"LoadBalancer:edge-alb",
		"支aaaaaaaaaaa", // mixed-width tail: the case that used to break
		"rôle-admin-café-x",
		"支払い管理者ロール",
		strings.Repeat("é", 20),
		"базы-данных-клиентов",
		"a",
		"",
	}
	for _, in := range cases {
		got := shortID(in)
		if !utf8.ValidString(got) {
			t.Errorf("shortID(%q) = %q, which is not valid UTF-8 - it would ship a broken YAML id", in, got)
		}
	}
}

// The test that should have been written first. Path ids embed shortID and one form
// (FindCriticalPaths) carries no hash, so two assets that shorten alike give two routes
// the same id - and then suppressing one suppresses the other. Trailing words like
// -admin and -db are the norm here, so this is the common case, not an exotic one.
func TestShortIDKeepsDistinctAssetsDistinct(t *testing.T) {
	groups := [][]string{
		{"payments-admin", "billing-admin", "customers-admin"},
		{"payments-db-prod", "customers-db-prod"},
		{"IAMRole:payments-admin", "IAMRole:billing-admin"},
		{"acme-web-frontend", "acme-api-frontend"},
	}
	for _, g := range groups {
		seen := map[string]string{}
		for _, name := range g {
			s := shortID(name)
			if prev, clash := seen[s]; clash {
				t.Errorf("shortID collapses %q and %q to %q - two routes to different assets "+
					"would share an id", prev, name, s)
			}
			seen[s] = name
		}
	}
}

// Short ids pass through untouched: shortening them would lose information for nothing.
func TestShortIDLeavesShortInputsAlone(t *testing.T) {
	for _, in := range []string{"", "a", "web-admin", "exactly12chr"} {
		if got := shortID(in); got != in {
			t.Errorf("shortID(%q) = %q, want it unchanged", in, got)
		}
	}
}

// Determinism: path ids are stored keys, so the same input must always shorten the same.
func TestShortIDIsDeterministic(t *testing.T) {
	const in = "some-quite-long-node-identifier"
	first := shortID(in)
	for i := 0; i < 100; i++ {
		if got := shortID(in); got != first {
			t.Fatalf("shortID is not deterministic: %q then %q", first, got)
		}
	}
}
