package api

import (
	"net/http"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
)

// Me is GET /auth/me: what the caller's credential resolved to, and whether it may change
// anything.
//
// The dashboard could not know this before. /auth/config describes the instance, not the
// person, so a viewer token was offered Suppress, Validate, Create ticket and Open fix PR
// as live buttons, pressed one, and met a 403 - the server was right and the page looked
// broken. CanWrite is the server's own write check, answered in advance, so the page can
// disable exactly what would be refused.
type Me struct {
	// Subject is how this caller appears in the audit log: "token:<fingerprint>" (never the
	// token), "jwt:<sub>", or "anonymous".
	Subject string `json:"subject"`
	// Role is viewer|operator|admin. Absent when the API has no authentication at all:
	// there is no role to report, and "none" would read as "no access".
	Role   string `json:"role,omitempty"`
	Tenant string `json:"tenant"`
	// Apps is the application allowlist this caller's reads are scoped to; absent means
	// every application in the tenant.
	Apps []string `json:"apps,omitempty"`
	// Anonymous is true when no credential was presented, which separates "this instance
	// takes no changes from visitors" from "your role takes no changes".
	Anonymous bool `json:"anonymous"`
	// CanWrite reports whether suppressions, tickets, validation verdicts and fix PRs
	// would be accepted from this caller.
	CanWrite bool `json:"canWrite"`
}

// handleAuthMe serves GET /auth/me. It sits behind the same authentication as the data
// it describes: a wrong or expired credential gets 401 here as everywhere else, and so
// counts toward the brute-force lockout like any other failed attempt. It tells a caller
// nothing about anyone but themselves.
func (a *API) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFromContext(r.Context())
	me := Me{
		Subject:   p.Subject,
		Tenant:    p.Tenant,
		Apps:      p.Apps,
		Anonymous: p.Subject == auth.AnonymousSubject,
		CanWrite:  a.adminWritable(r),
	}
	if a.authEnabled() {
		me.Role = p.Role.String()
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, me)
}
