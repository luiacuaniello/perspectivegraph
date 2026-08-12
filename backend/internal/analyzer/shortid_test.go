package analyzer

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// These ids leave the product. They are embedded in the id: of the generated Sigma rule
// and the tags: and output: of the Falco rule, and they key every suppression, ticket,
// verdict and audit record. So the properties below are about what a user deploys and
// stores, not about an internal string.

// stem is the readable half. It must stay valid UTF-8 whatever it is handed - the earlier
// version sliced the last N runes off a byte string and could split a multi-byte
// character, shipping a broken YAML id.
func TestStemNeverProducesInvalidUTF8(t *testing.T) {
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
		got := stem(in)
		if !utf8.ValidString(got) {
			t.Errorf("stem(%q) = %q, which is not valid UTF-8 - it would ship a broken YAML id", in, got)
		}
	}
}

// The readability property, which is the whole reason stem exists.
//
// Node ids are "<Label>:<name>". Keeping the last runes of the WHOLE id cut through both:
// "IAM_Role:payments-admin" became "yments-admin" and "LoadBalancer:edge-alb" became
// "cer:edge-alb" - strings that read as corruption in a file somebody pastes into a SIEM.
func TestStemKeepsTheAssetNameIntact(t *testing.T) {
	for in, want := range map[string]string{
		"IAM_Role:payments-admin":      "payments-admin",
		"LoadBalancer:edge-alb":        "edge-alb",
		"Container:payments":           "payments",
		"ServiceAccount:cluster-admin": "cluster-admin",
		"payments-admin":               "payments-admin",
	} {
		if got := stem(in); got != want {
			t.Errorf("stem(%q) = %q, want %q", in, got, want)
		}
	}
}

// A stem long enough to need cutting is cut on a separator, not through a word.
func TestStemCutsOnASeparator(t *testing.T) {
	got := stem("IAM_Role:payments-admin-emea-production-role")
	if strings.HasSuffix(got, "-") || len(got) == 0 {
		t.Fatalf("stem produced %q", got)
	}
	if !strings.HasPrefix("payments-admin-emea-production-role", got) {
		t.Errorf("stem(%q) = %q - it should be a prefix of the name, not a slice out of its middle", "payments-admin-emea-production-role", got)
	}
}

// THE property that matters, and the one that used to be missing.
//
// The critical-path builder composed an id from its two endpoints alone, so two different
// assets that shorten alike produced the same id for different routes - and suppressing
// one would suppress the other. The previous test only covered assets sharing a label
// prefix; the case that actually bit is the opposite one, two DIFFERENT labels wrapping
// the same name, which stem now deliberately collapses. The hash is what separates them.
func TestPathIDKeepsDistinctRoutesDistinct(t *testing.T) {
	groups := [][][]string{
		// Same asset name under different labels - stems collide by design, ids must not.
		{
			{"LoadBalancer:edge-alb", "IAM_Role:payments-admin"},
			{"LoadBalancer:edge-alb", "ServiceAccount:payments-admin"},
		},
		// Names that shorten alike.
		{
			{"LoadBalancer:edge-alb", "IAM_Role:payments-admin"},
			{"LoadBalancer:edge-alb", "IAM_Role:billing-admin"},
		},
		// Same endpoints, different route between them: the reason a hash of the WHOLE
		// path is needed rather than a hash of its ends.
		{
			{"LoadBalancer:edge-alb", "Container:payments", "IAM_Role:payments-admin"},
			{"LoadBalancer:edge-alb", "Container:web", "IAM_Role:payments-admin"},
		},
	}
	for _, g := range groups {
		seen := map[string][]string{}
		for _, seq := range g {
			id := pathID(seq)
			if prev, clash := seen[id]; clash {
				t.Errorf("pathID collapses %v and %v to %q - suppressing one would suppress the other", prev, seq, id)
			}
			seen[id] = seq
		}
	}
}

// Determinism: path ids are stored keys, so the same route must always produce the same
// id - across runs, and across the two builders that make them.
func TestPathIDIsDeterministic(t *testing.T) {
	seq := []string{"LoadBalancer:edge-alb", "Container:payments", "IAM_Role:payments-admin"}
	first := pathID(seq)
	for i := 0; i < 100; i++ {
		if got := pathID(seq); got != first {
			t.Fatalf("pathID is not deterministic: %q then %q", first, got)
		}
	}
	// And it reads as an identifier a human can recognise in a Sigma rule.
	if !strings.HasPrefix(first, "ap-edge-alb-payments-admin-") {
		t.Errorf("pathID = %q, want it to name both endpoints readably", first)
	}
}

// An empty route must not panic or produce a bare "ap--".
func TestPathIDHandlesTheEmptyRoute(t *testing.T) {
	if got := pathID(nil); got == "" || strings.Contains(got, "--") {
		t.Errorf("pathID(nil) = %q", got)
	}
}
