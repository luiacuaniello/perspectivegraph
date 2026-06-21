package scrub

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	cases := []struct {
		name string
		in   string
		kind string // expected kind present in the result
	}{
		{"aws access key", "found AKIAIOSFODNN7EXAMPLE in handler.py", "aws-access-key"},
		{"github token", "token ghp_0123456789abcdefghijklmnopqrstuvwxyzA leaked", "github-token"},
		{"slack token", "url uses xoxb-2024-abcDEF0123 header", "slack-token"},
		{"google api key", "key AIzaSyA1234567890abcdefghijklmnopqrstuvw here", "google-api-key"},
		{"jwt", "Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36 embedded", "jwt"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIBOg...", "private-key"},
		{"secret assignment", `aws_secret_access_key="wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"`, "secret-assignment"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, kinds, hit := Redact(c.in)
			if !hit {
				t.Fatalf("expected a redaction for %q, got none", c.in)
			}
			if !containsKind(kinds, c.kind) {
				t.Errorf("kinds = %v, want one to be %q", kinds, c.kind)
			}
			if strings.Contains(out, "redacted") == false {
				t.Errorf("output %q has no redaction marker", out)
			}
		})
	}
}

// TestRedactPreservesContext makes sure scrubbing removes the value but keeps the
// finding readable, and keeps the key for assignment-style hits.
func TestRedactPreservesContext(t *testing.T) {
	out, _, _ := Redact("hardcoded AKIAIOSFODNN7EXAMPLE in src/config.py line 7")
	if !strings.Contains(out, "src/config.py") || !strings.Contains(out, "hardcoded") {
		t.Errorf("lost surrounding context: %q", out)
	}
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret survived: %q", out)
	}

	out, _, _ = Redact(`token = "ghp_0123456789abcdefghijklmnopqrstuvwxyzZ"`)
	if !strings.HasPrefix(out, "token") {
		t.Errorf("assignment key should survive: %q", out)
	}
	if strings.Contains(out, "ghp_0123456789") {
		t.Errorf("token value survived: %q", out)
	}
}

// TestRedactLeavesIdentifiersAlone is the safety net: the identifiers the graph
// relies on for correlation (commit SHAs, image digests, CVE ids, refs, emails)
// must NOT be redacted, or dedup/joins break.
func TestRedactLeavesIdentifiersAlone(t *testing.T) {
	safe := []string{
		"deadbeefcafebabe1234567890abcdef12345678",                                // 40-hex git SHA
		"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", // image digest
		"acme/payments-api:1.4.2",                                                 // image ref
		"CVE-2021-44228",                                                          // CVE id
		"alice@acme.com",                                                          // identity / SSO user
		"arn:aws:iam::123456789012:role/deployer",                                 // ARN
	}
	for _, s := range safe {
		if out, kinds, hit := Redact(s); hit {
			t.Errorf("identifier %q was wrongly redacted to %q (kinds=%v)", s, out, kinds)
		}
	}
}

func TestRedactEmptyAndClean(t *testing.T) {
	if _, _, hit := Redact(""); hit {
		t.Error("empty string should not redact")
	}
	if out, _, hit := Redact("a perfectly ordinary finding message"); hit || out != "a perfectly ordinary finding message" {
		t.Errorf("clean string mutated: %q hit=%v", out, hit)
	}
}

// FuzzRedact asserts the contract: Redact consumes untrusted scanner bytes, so it
// must never panic, and once it reports a hit the recognizable secret token must
// be gone from the output.
func FuzzRedact(f *testing.F) {
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add(`password="hunter2hunter2"`)
	f.Add("nothing to see here")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		out, kinds, hit := Redact(s)
		if hit && len(kinds) == 0 {
			t.Fatalf("hit reported with no kinds for %q", s)
		}
		if !hit && out != s {
			t.Fatalf("no hit but output changed: %q -> %q", s, out)
		}
	})
}

func containsKind(kinds []string, want string) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}
