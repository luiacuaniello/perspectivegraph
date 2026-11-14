// Package tenant is how a tenant is named past authentication: one spelling, everywhere.
//
// A tenant used to have two. The graph, the analyzer, the history and the search index
// keyed it by its normalized form, while the governance stores (suppressions, tickets,
// validations) and the coverage ledger kept it as the token spelt it. Every reader had to
// know which store took which, and the October fixes to search and history were readers
// that guessed wrong and found nothing. Authentication now normalizes the tenant once,
// and the governance stores normalize what they are handed as well, so a new reader
// cannot reach one under the other spelling.
package tenant

import "strings"

// Default is the tenant of a principal that names none.
const Default = "default"

// Normalize is a tenant's one spelling: trimmed, lower case, every character outside
// [a-z0-9_] replaced by an underscore, and Default for an empty name. "Acme-Corp" and
// "acme corp" are both "acme_corp" - which is why startup refuses two configured names that
// differ beyond case and normalize alike (they would be one tenant).
func Normalize(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" {
		return Default
	}
	var b strings.Builder
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
