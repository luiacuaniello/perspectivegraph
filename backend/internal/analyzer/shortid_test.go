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

// A fragment cut mid-word ("yments-admin") is what a user reads in every artifact for
// that path, so the shortening starts at a separator when it can.
func TestShortIDDoesNotCutMidWord(t *testing.T) {
	if got := shortID("payments-admin"); got != "admin" {
		t.Errorf("shortID(\"payments-admin\") = %q, want %q", got, "admin")
	}
	if got := shortID("LoadBalancer:edge-alb"); got != "edge-alb" {
		t.Errorf("shortID(\"LoadBalancer:edge-alb\") = %q, want %q", got, "edge-alb")
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
