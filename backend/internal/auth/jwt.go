package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/luiacuaniello/perspectivegraph/internal/httpx"
)

// JWTConfig configures OIDC/JWT authentication.
type JWTConfig struct {
	JWKSURL     string // OIDC JWKS endpoint (RS256 public keys)
	Issuer      string // expected "iss" (optional but recommended)
	Audience    string // expected "aud" (optional but recommended)
	RoleClaim   string // claim holding the role (default "role")
	TenantClaim string // claim holding the tenant (default "tenant")
	AppsClaim   string // claim holding the application allowlist (default "apps")
	DefaultRole Role   // role when the token has no role claim
}

// JWTAuthenticator verifies RS256 JWTs against a cached JWKS and maps the
// claims to a Principal.
type JWTAuthenticator struct {
	cfg  JWTConfig
	keys *jwksCache
}

func NewJWTAuthenticator(cfg JWTConfig) *JWTAuthenticator {
	if cfg.RoleClaim == "" {
		cfg.RoleClaim = "role"
	}
	if cfg.TenantClaim == "" {
		cfg.TenantClaim = "tenant"
	}
	if cfg.AppsClaim == "" {
		cfg.AppsClaim = "apps"
	}
	return &JWTAuthenticator{cfg: cfg, keys: newJWKSCache(cfg.JWKSURL)}
}

func (j *JWTAuthenticator) Enabled() bool { return j.cfg.JWKSURL != "" }

func (j *JWTAuthenticator) Authenticate(r *http.Request) (Principal, bool) {
	raw := bearer(r)
	// JWTs have three dot-separated parts; skip opaque static tokens cheaply.
	if raw == "" || len(splitN(raw, '.')) != 3 {
		return Principal{}, false
	}

	claims := jwt.MapClaims{}
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"})}
	if j.cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(j.cfg.Issuer))
	}
	if j.cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(j.cfg.Audience))
	}
	tok, err := jwt.ParseWithClaims(raw, claims, j.keys.keyfunc(r.Context()), opts...)
	if err != nil || !tok.Valid {
		return Principal{}, false
	}

	role := j.cfg.DefaultRole
	if v, ok := claims[j.cfg.RoleClaim].(string); ok {
		if parsed, ok := parseRole(v); ok {
			role = parsed
		}
	}
	tenant := DefaultTenant
	if v, ok := claims[j.cfg.TenantClaim].(string); ok && v != "" {
		tenant = v
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		sub = "jwt"
	}
	return Principal{Subject: "jwt:" + sub, Role: role, Tenant: tenant, Apps: parseAppsClaim(claims[j.cfg.AppsClaim])}, true
}

// parseAppsClaim accepts the apps allowlist as a JSON array of strings or as a
// single delimited string (comma/space/pipe-separated).
func parseAppsClaim(v any) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ' ' || r == '|' })
	}
	return nil
}

func splitN(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// ── JWKS cache (minimal, RSA) ────────────────────────────────────────

type jwksCache struct {
	url    string
	client *http.Client // dedicated client with a timeout — never http.DefaultClient

	refreshMu sync.Mutex // serializes refreshes so a stale cache triggers one fetch, not a herd

	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey // kid -> key
	fetched time.Time
}

func newJWKSCache(url string) *jwksCache {
	// A hanging IdP must not stall the auth path: bound the JWKS fetch explicitly
	// (http.DefaultClient has no timeout).
	return &jwksCache{url: url, client: &http.Client{Timeout: 15 * time.Second}, keys: map[string]*rsa.PublicKey{}}
}

const jwksTTL = time.Hour

// jwksMinRefetch rate-limits the refetch-on-unknown-kid path: when a token's kid
// isn't cached (the IdP rotated signing keys), we refetch the JWKS to pick up the
// new key promptly instead of rejecting valid tokens until the hour-long TTL
// lapses — but not more than once per this interval, so a flood of tokens bearing
// bogus kids can't turn the auth path into a JWKS-fetch amplifier.
const jwksMinRefetch = time.Minute

// keyfunc returns a jwt.Keyfunc that resolves the signing key by "kid",
// refetching the JWKS on a cache miss or when stale.
func (c *jwksCache) keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if key := c.get(kid); key != nil {
			return key, nil
		}
		if err := c.refreshOnce(ctx); err != nil {
			return nil, err
		}
		if key := c.get(kid); key != nil {
			return key, nil
		}
		return nil, fmt.Errorf("jwks: no key for kid %q", kid)
	}
}

// refreshOnce serializes concurrent refreshes: the first waiter fetches, the rest
// observe the now-fresh cache and return without a second network call. It is only
// reached on a cache miss (unknown kid), so it refetches unless the JWKS was
// already pulled within jwksMinRefetch — that picks up rotated keys within a
// minute while still rate-limiting bogus-kid spam (the hour-long jwksTTL governs
// proactive staleness of already-known keys, see get).
func (c *jwksCache) refreshOnce(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.mu.RLock()
	recent := len(c.keys) > 0 && time.Since(c.fetched) <= jwksMinRefetch
	c.mu.RUnlock()
	if recent {
		return nil
	}
	return c.refresh(ctx)
}

func (c *jwksCache) get(kid string) *rsa.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Since(c.fetched) > jwksTTL {
		return nil // force a refresh
	}
	return c.keys[kid]
}

func (c *jwksCache) refresh(ctx context.Context) error {
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := httpx.Do(ctx, c.client, http.MethodGet, c.url, nil, "", nil, &doc); err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
	}
	c.mu.Lock()
	c.keys, c.fetched = keys, time.Now()
	c.mu.Unlock()
	return nil
}
