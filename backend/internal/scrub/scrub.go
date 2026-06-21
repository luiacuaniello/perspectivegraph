// Package scrub redacts secret-looking values out of free text before it is
// persisted.
//
// PerspectiveGraph ingests the raw output of scanners (Trivy, Semgrep, Falco, …)
// and cloud exports. That output can incidentally carry a live credential — a
// hardcoded AWS key in a Semgrep snippet, a token on a Falco command line, a
// private key in a config asset. The graph is a map of how to attack the org, so
// the one thing it must never become is a *store of the secrets themselves*: a
// single read of the attack map would then hand an attacker working credentials.
//
// Redact masks high-precision secret patterns (and `secret=…` style assignments)
// while leaving the surrounding finding intact — you still learn "an AWS key is
// hardcoded in config.py:7", you just don't learn the key. Patterns are kept
// deliberately specific so they never collide with the git SHAs, image digests,
// and refs the graph legitimately stores for correlation.
package scrub

import (
	"regexp"
	"sort"
)

type pattern struct {
	kind string
	re   *regexp.Regexp
	// repl is the replacement template (regexp.ReplaceAllString semantics, so $1
	// etc. refer to capture groups). Empty means replace the whole match with the
	// standard marker for this kind.
	repl string
}

// marker is what a redacted secret is replaced with. It records *that* a secret
// was present (and its class) without disclosing the value.
func marker(kind string) string { return "***redacted:" + kind + "***" }

// patterns are ordered most-specific first. Each is anchored on a structural
// signature (a vendor prefix, a PEM header, a JWT shape, or an explicit
// key/secret/token assignment) — never a bare "looks like base64/hex", which
// would shred commit SHAs and sha256 digests.
var patterns = []pattern{
	// AWS access key id (AKIA…) and temporary id (ASIA…).
	{kind: "aws-access-key", re: regexp.MustCompile(`\bA[SK]IA[0-9A-Z]{16}\b`)},
	// GitHub personal/OAuth/server/refresh tokens.
	{kind: "github-token", re: regexp.MustCompile(`\bgh[posru]_[A-Za-z0-9]{36,}\b`)},
	// Slack bot/user/app tokens.
	{kind: "slack-token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	// Google API key (AIza + 35 chars).
	{kind: "google-api-key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}`)},
	// JSON Web Token (header.payload.signature).
	{kind: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	// PEM private-key block header (the rest of the block follows it).
	{kind: "private-key", re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	// Generic `password|secret|api_key|access_key|token = VALUE` assignment: mask
	// only the value, keep the key + separator so the finding still reads. No
	// leading \b — the keyword is routinely embedded in a snake_case identifier
	// (aws_secret_access_key, db_password). The trailing separator+value structure
	// is what gates a match, so prose like "my password is good" is left alone.
	// Value must be 8+ non-space chars to avoid eating version tags and short flags.
	{
		kind: "secret-assignment",
		re:   regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|token)(\s*[:=]\s*"?)([^\s"',]{8,})`),
		repl: "$1$2" + marker("secret"),
	},
}

// Redact masks every secret-looking substring in s. It returns the cleaned
// string, the sorted, deduplicated kinds of secret that were found, and whether
// anything was masked. It is a pure function — safe to call on untrusted input,
// and it never panics.
func Redact(s string) (string, []string, bool) {
	if s == "" {
		return s, nil, false
	}
	out := s
	seen := map[string]bool{}
	for _, p := range patterns {
		if !p.re.MatchString(out) {
			continue
		}
		seen[p.kind] = true
		if p.repl != "" {
			out = p.re.ReplaceAllString(out, p.repl)
		} else {
			out = p.re.ReplaceAllString(out, marker(p.kind))
		}
	}
	if len(seen) == 0 {
		return s, nil, false
	}
	kinds := make([]string, 0, len(seen))
	for k := range seen {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return out, kinds, true
}
