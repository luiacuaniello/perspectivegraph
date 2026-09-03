package action

import (
	"errors"
	"fmt"
	"strings"
)

// This file is the single place that decides WHERE the engine is allowed to write.
//
// Everything else in this package takes its destination from a node property
// (`repo_slug`), and node properties come from the ingest path - a scanner in CI,
// holding a shared HMAC key, is the least-trusted credential in the deployment. So
// without a guard the destination of an authenticated write is chosen by whoever can
// post an event: plant a node carrying someone else's slug and the engine comments,
// posts a commit status, or opens a pull request there, with the operator's token.
//
// The commit status is the sharp end. A `success` posted on a commit in a repository
// where this check is REQUIRED is a merge gate opening - the exact control the PR-check
// feature exists to provide, turned around.
//
// The guard is therefore an operator-configured allowlist and it FAILS CLOSED: no
// allowlist means no writes. That is a deliberate behaviour change over versions that
// wrote wherever the graph pointed. An operator knows which repositories are theirs;
// the engine cannot know, and guessing from untrusted data is how this went wrong.

// ErrRepoNotAllowed is returned when a write is refused because its repository is not
// in the configured allowlist. Callers surface it as a configuration problem, not a
// transport failure - retrying will not help.
var ErrRepoNotAllowed = errors.New("repository not in REPO_ALLOWLIST")

// maxSlugSegment and maxSlugLen bound one path segment and the whole slug. GitHub caps
// owners at 39 and repositories at 100; GitLab allows nested groups, so the slug may
// carry more than two segments and the bound is on the total.
const (
	maxSlugSegment = 100
	maxSlugLen     = 200
	maxSlugParts   = 4
)

// ValidSlug reports whether s is a well-formed repository path: two to four segments
// of the forge's own charset, no empty segment, and no "." or ".." anywhere.
//
// The dot-segment rule is not cosmetic. The GitHub calls interpolate the slug straight
// into a URL path, so a slug containing ".." is a request for a different endpoint once
// the server resolves it - a validated slug is what makes that interpolation safe.
func ValidSlug(s string) bool {
	if s == "" || len(s) > maxSlugLen {
		return false
	}
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > maxSlugParts {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || len(p) > maxSlugSegment {
			return false
		}
		for i := 0; i < len(p); i++ {
			c := p[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
				c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
			if !ok {
				return false
			}
		}
	}
	return true
}

// RepoAllow is the allowlist of repositories the engine may write to. Entries are
// either an exact slug ("acme/payments-api") or an owner wildcard ("acme/*"), which
// keeps an organisation with hundreds of repositories to one entry without ever
// widening past an owner the operator named.
//
// The zero value and a nil *RepoAllow both deny everything. That is the point: a call
// site that forgets to pass the guard refuses to write rather than writing anywhere.
type RepoAllow struct {
	exact  map[string]bool
	owners map[string]bool
}

// NewRepoAllow parses the configured patterns. An invalid pattern is an error rather
// than a silently ignored entry: a typo that drops a repository from the allowlist
// would otherwise show up as writes quietly not happening.
func NewRepoAllow(patterns []string) (*RepoAllow, error) {
	a := &RepoAllow{exact: map[string]bool{}, owners: map[string]bool{}}
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		if owner, ok := strings.CutSuffix(p, "/*"); ok {
			if owner == "" || strings.Contains(owner, "/") || !ValidSlug(owner+"/x") {
				return nil, fmt.Errorf("invalid repo allowlist owner wildcard %q", raw)
			}
			a.owners[strings.ToLower(owner)] = true
			continue
		}
		if !ValidSlug(p) {
			return nil, fmt.Errorf("invalid repo allowlist entry %q (want owner/repo or owner/*)", raw)
		}
		a.exact[strings.ToLower(p)] = true
	}
	return a, nil
}

// Configured reports whether any entry was supplied, so startup can say plainly that
// the forge writers are configured but will refuse every write.
func (a *RepoAllow) Configured() bool {
	return a != nil && (len(a.exact) > 0 || len(a.owners) > 0)
}

// Permit reports whether the engine may write to slug. It validates the shape first,
// so a malformed slug is refused even by an allowlist that would otherwise match.
func (a *RepoAllow) Permit(slug string) bool {
	if a == nil || !ValidSlug(slug) {
		return false
	}
	s := strings.ToLower(slug)
	if a.exact[s] {
		return true
	}
	owner, _, _ := strings.Cut(s, "/")
	return a.owners[owner]
}
