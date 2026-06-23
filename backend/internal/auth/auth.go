// Package auth secures the two front doors and resolves the caller's identity:
//
//   - the ingest webhook (write path) with a per-tenant HMAC-SHA256 signature
//     over the request body - the secret never travels on the wire;
//   - the GraphQL API (read path) with bearer credentials, either static tokens
//     or OIDC/JWT, mapped to an RBAC role and a tenant.
//
// Everything resolves to a Principal {Subject, Role, Tenant} carried on the
// request context, so multi-tenancy and audit work uniformly regardless of how
// the caller authenticated. All doors are opt-in: unset → open (dev), and main
// logs a loud warning. Authenticated requests are written to the audit log.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
)

// DefaultTenant is the tenant used when auth is open or no tenant is specified.
const DefaultTenant = "default"

// Role is an RBAC role; higher value = more privilege.
type Role int

const (
	RoleNone Role = iota
	RoleViewer
	RoleOperator
	RoleAdmin
)

func (r Role) String() string {
	switch r {
	case RoleViewer:
		return "viewer"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	default:
		return "none"
	}
}

func parseRole(s string) (Role, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "viewer":
		return RoleViewer, true
	case "operator":
		return RoleOperator, true
	case "admin":
		return RoleAdmin, true
	}
	return RoleNone, false
}

// Principal is the authenticated identity on a request.
type Principal struct {
	Subject string // token fingerprint, JWT sub, or "hmac"
	Role    Role
	Tenant  string
	// Apps, when non-empty, restricts read access to attack paths / assets that
	// touch one of these applications (object-level RBAC within a tenant). Empty
	// means unrestricted (all applications in the tenant).
	Apps []string
}

type ctxKey struct{}

// WithPrincipal stores p on the context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// PrincipalFromContext returns the principal, or a DefaultTenant principal when
// auth is open (so downstream code always has a tenant to route by).
func PrincipalFromContext(ctx context.Context) Principal {
	if p, ok := ctx.Value(ctxKey{}).(Principal); ok {
		return p
	}
	return Principal{Subject: "anonymous", Tenant: DefaultTenant}
}

// Authenticator resolves a request to a Principal.
type Authenticator interface {
	Authenticate(r *http.Request) (Principal, bool)
	Enabled() bool
}

// Chain tries each authenticator in order (e.g. static tokens, then JWT).
type Chain []Authenticator

func (c Chain) Enabled() bool {
	for _, a := range c {
		if a != nil && a.Enabled() {
			return true
		}
	}
	return false
}

func (c Chain) Authenticate(r *http.Request) (Principal, bool) {
	for _, a := range c {
		if a == nil || !a.Enabled() {
			continue
		}
		if p, ok := a.Authenticate(r); ok {
			return p, true
		}
	}
	return Principal{}, false
}

// ── static bearer tokens → role + tenant ────────────────────────────

// TokenStore maps bearer tokens to a Principal, parsed from a spec of
// comma-separated entries:
//
//		token:role[:tenant[:expiry[:app1|app2]]]
//
//	  - token  - the bearer value, OR "sha256$<hex>" to store only a hash of it
//	    (so the live secret never sits in config/env at rest).
//	  - role   - viewer | operator | admin.
//	  - tenant - optional (defaults to DefaultTenant; empty field keeps the default).
//	  - expiry - optional YYYY-MM-DD; the token is rejected after the end of that
//	    UTC day (token lifecycle / rotation).
//	  - apps   - optional pipe-separated application allowlist; the principal can
//	    only read attack paths / assets touching one of these apps (object RBAC).
type TokenStore struct {
	entries []tokenEntry
	now     func() time.Time
}

type tokenEntry struct {
	hashed    bool      // value is a sha256 hex digest, not the raw token
	value     string    // raw token (plaintext) or lowercase hex digest (hashed)
	principal Principal // role + tenant + apps resolved at parse time
	expiry    time.Time // zero = no expiry
}

func NewTokenStore(spec string) *TokenStore {
	ts := &TokenStore{now: time.Now}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) < 2 || parts[0] == "" {
			slog.Warn("auth: ignoring malformed API_TOKENS entry (need token:role…)")
			continue
		}
		role, ok := parseRole(parts[1])
		if !ok {
			slog.Warn("auth: ignoring API_TOKENS entry with unknown role", "role", parts[1])
			continue
		}
		tenant := DefaultTenant
		if len(parts) >= 3 && parts[2] != "" {
			tenant = parts[2]
		}
		var expiry time.Time
		if len(parts) >= 4 && parts[3] != "" {
			d, err := time.Parse("2006-01-02", parts[3])
			if err != nil {
				slog.Warn("auth: ignoring API_TOKENS entry with bad expiry (want YYYY-MM-DD)", "expiry", parts[3])
				continue
			}
			expiry = d.UTC().Add(24 * time.Hour) // valid through the end of that UTC day
		}
		var apps []string
		if len(parts) >= 5 && parts[4] != "" {
			for _, a := range strings.Split(parts[4], "|") {
				if a = strings.TrimSpace(a); a != "" {
					apps = append(apps, a)
				}
			}
		}
		hashed, value := false, parts[0]
		if h, isHash := strings.CutPrefix(parts[0], "sha256$"); isHash {
			hashed, value = true, strings.ToLower(strings.TrimSpace(h))
		}
		ts.entries = append(ts.entries, tokenEntry{
			hashed: hashed, value: value, expiry: expiry,
			principal: Principal{Subject: "token:" + fingerprint(value), Role: role, Tenant: tenant, Apps: apps},
		})
	}
	return ts
}

func (t *TokenStore) Enabled() bool { return len(t.entries) > 0 }

func (t *TokenStore) Authenticate(r *http.Request) (Principal, bool) {
	provided := bearer(r)
	if provided == "" {
		return Principal{}, false
	}
	presentedHash := sha256Hex(provided)
	now := t.now()
	// Constant-time compare so timing can't distinguish a near-match from a miss.
	var found Principal
	ok := false
	for _, e := range t.entries {
		cmp := provided
		if e.hashed {
			cmp = presentedHash
		}
		if subtle.ConstantTimeCompare([]byte(cmp), []byte(e.value)) != 1 {
			continue
		}
		if !e.expiry.IsZero() && !now.Before(e.expiry) {
			continue // matched, but the token has expired
		}
		found, ok = e.principal, true
	}
	return found, ok
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func fingerprint(s string) string { return sha256Hex(s)[:8] }

func bearer(r *http.Request) string {
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// ── role-gated API middleware ───────────────────────────────────────

// RequireRole authenticates the request, checks the role, stores the principal
// on the context, audits the access, and calls next. OPTIONS passes through.
// guard (nil-safe) locks out an IP that exceeds the failed-attempt threshold,
// blunting credential brute force before the (constant-time) token check runs.
func RequireRole(authn Authenticator, min Role, rec audit.Recorder, guard *secwatch.Watcher, next http.Handler) http.Handler {
	if rec == nil {
		rec = audit.Nop{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientIPHost(r)
		if guard.Tripped(ip) {
			rec.Record("auth.locked", "unknown", "", "", map[string]any{"path": r.URL.Path, "remote": ip})
			tooManyRequests(w)
			return
		}
		p, ok := authn.Authenticate(r)
		if !ok || p.Role < min {
			rec.Record("auth.deny", "unknown", "", "", map[string]any{"path": r.URL.Path, "remote": ip})
			// Only a *rejected credential* counts toward the brute-force lockout -
			// i.e. a bearer token was presented and authentication failed (!ok). An
			// anonymous request (no Authorization header) isn't credential guessing,
			// and a valid token with an insufficient role (ok but p.Role < min) is an
			// authorization miss, not a brute-force attempt. Counting either would let
			// a login-gated SPA polling before sign-in - or any unauthenticated
			// client - trip the lockout on itself; raw request volume is already
			// bounded by the per-IP rate limiter.
			if !ok && bearer(r) != "" {
				guard.Observe(ip, 1) // may trip the lockout + alert
			}
			unauthorized(w, "invalid or insufficient credentials")
			return
		}
		rec.Record("api", p.Subject, p.Role.String(), p.Tenant,
			map[string]any{"method": r.Method, "path": r.URL.Path, "remote": ip})
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"errors":[{"message":"unauthorized: ` + msg + `"}]}`))
}

func tooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"errors":[{"message":"too many failed attempts - temporarily locked out"}]}`))
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	return r.RemoteAddr
}

// clientIPHost is clientIP without the source port, so a brute-forcer rotating
// connections (each a new ephemeral port) is still keyed to one host for lockout.
func clientIPHost(r *http.Request) string {
	ip := clientIP(r)
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}
