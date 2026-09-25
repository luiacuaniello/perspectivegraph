package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
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
//
// Issuer and Audience are structurally optional here - this type cannot enforce them,
// and leaving them empty simply skips the corresponding check - but the binary REFUSES
// TO START if JWKSURL is set without both (see checkAuthConfig in cmd/perspectivegraph).
// They are not a recommendation. Skipping audience validation means accepting any token
// the IdP ever minted, including tokens issued to a different relying party sharing the
// same JWKS: another application's user silently becomes this one's, carrying whatever
// role and tenant claims their token happens to hold.
type JWTConfig struct {
	JWKSURL string // OIDC JWKS endpoint (RS256 public keys)
	// Issuer and Audience are REQUIRED whenever JWKSURL is set; the startup gate
	// enforces it. See the type comment for what skipping them actually costs.
	Issuer      string // expected "iss"
	Audience    string // expected "aud"
	RoleClaim   string // claim holding the role (default "role")
	TenantClaim string // claim holding the tenant (default "tenant")
	AppsClaim   string // claim holding the application allowlist (default "apps")

	// GroupsClaim and GroupRoles map directory groups onto roles, because that is
	// where enterprise IdPs actually keep authorisation. Okta and Entra hand out
	// `groups: ["sec-eng", "pg-admins"]`; neither mints a `role` claim unless someone
	// builds a custom mapping in the IdP first. Without this, every SSO user arrived
	// with no role and saw nothing, and the fix lived in a system this project does
	// not own.
	//
	// GroupRoles is group -> role. A subject in several mapped groups gets the
	// HIGHEST role among them, which is what group membership already means to the
	// people who grant it: adding someone to the admins group is not expected to be
	// undone by their also being in viewers.
	GroupsClaim string // claim holding the group list (default "groups")
	GroupRoles  map[string]Role

	// DefaultRole is the role for a token that matches nothing above. It stays
	// RoleNone unless an operator sets it: authenticating at the IdP proves who
	// someone is, not that they may read a map of how to attack the organisation.
	// Granting everyone the IdP admits a role has to be a decision somebody makes.
	DefaultRole Role
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
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
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
	// Asymmetric algorithms only: RSA, and ECDSA for identity providers that sign with
	// EC keys (ES256 is a common default). Never HS* - the JWKS is public - and never
	// "none". keyfunc also checks each algorithm against its key's type and curve.
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"})}
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

	role := j.roleFrom(claims)
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

// roleFrom resolves the role a token grants, from the role claim and the group claim
// together. The highest role any source grants wins, and nothing granting anything means
// DefaultRole - which is RoleNone unless an operator deliberately widened it.
//
// Both sources are read from the same signed token, so preferring one over the other
// would buy no security, only surprise: a subject who is in the admins group AND carries
// role=viewer is someone whose directory says admin, and the directory is what the
// people granting access actually edit.
func (j *JWTAuthenticator) roleFrom(claims jwt.MapClaims) Role {
	role := j.cfg.DefaultRole
	if v, ok := claims[j.cfg.RoleClaim].(string); ok {
		if parsed, ok := parseRole(v); ok && parsed > role {
			role = parsed
		}
	}
	if len(j.cfg.GroupRoles) == 0 {
		return role
	}
	for _, g := range parseAppsClaim(claims[j.cfg.GroupsClaim]) {
		if mapped, ok := j.cfg.GroupRoles[g]; ok && mapped > role {
			role = mapped
		}
	}
	return role
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
	client *http.Client // dedicated client with a timeout - never http.DefaultClient

	refreshMu sync.Mutex // serializes refreshes so a stale cache triggers one fetch, not a herd

	mu      sync.RWMutex
	keys    map[string]crypto.PublicKey // kid -> *rsa.PublicKey or *ecdsa.PublicKey
	fetched time.Time
}

func newJWKSCache(url string) *jwksCache {
	// A hanging IdP must not stall the auth path: bound the JWKS fetch explicitly
	// (http.DefaultClient has no timeout).
	return &jwksCache{url: url, client: &http.Client{Timeout: 15 * time.Second}, keys: map[string]crypto.PublicKey{}}
}

const jwksTTL = time.Hour

// jwksMinRefetch rate-limits the refetch-on-unknown-kid path: when a token's kid
// isn't cached (the IdP rotated signing keys), we refetch the JWKS to pick up the
// new key promptly instead of rejecting valid tokens until the hour-long TTL
// lapses - but not more than once per this interval, so a flood of tokens bearing
// bogus kids can't turn the auth path into a JWKS-fetch amplifier.
const jwksMinRefetch = time.Minute

// keyfunc returns a jwt.Keyfunc that resolves the signing key by "kid",
// refetching the JWKS on a cache miss or when stale.
func (c *jwksCache) keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		key := c.get(kid)
		if key == nil {
			if err := c.refreshOnce(ctx); err != nil {
				return nil, err
			}
			key = c.get(kid)
		}
		if key == nil {
			return nil, fmt.Errorf("jwks: no key for kid %q", kid)
		}
		if err := keyFitsAlg(key, token.Method.Alg()); err != nil {
			return nil, err
		}
		return key, nil
	}
}

// keyFitsAlg refuses a token whose algorithm does not match the key it names: RS* needs
// an RSA key, and ES256/384/512 an EC key on P-256/384/521. The JWT library refuses the
// same mismatches inside each signing method (measured); this keeps the rule where the
// key is chosen, so it does not rest on every method's implementation getting it right.
func keyFitsAlg(key crypto.PublicKey, alg string) error {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "RS") {
			return nil
		}
	case *ecdsa.PublicKey:
		want := map[string]string{"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[alg]
		if want != "" && k.Curve.Params().Name == want {
			return nil
		}
	}
	return fmt.Errorf("jwks: key does not fit algorithm %q", alg)
}

// refreshOnce serializes concurrent refreshes: the first waiter fetches, the rest
// observe the now-fresh cache and return without a second network call. It is only
// reached on a cache miss (unknown kid), so it refetches unless the JWKS was
// already pulled within jwksMinRefetch - that picks up rotated keys within a
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

func (c *jwksCache) get(kid string) crypto.PublicKey {
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
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := httpx.Do(ctx, c.client, http.MethodGet, c.url, nil, "", nil, &doc); err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty == "EC" {
			if key, err := ecKey(k.Crv, k.X, k.Y); err == nil {
				keys[k.Kid] = key
			}
			continue
		}
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

// ecKey builds an EC public key from a JWK's curve and coordinates. The point is
// validated - a point off the curve is refused - by decoding it as an uncompressed point.
func ecKey(crv, x, y string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve %q", crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, err
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(xb) > size || len(yb) > size {
		return nil, errors.New("EC coordinate longer than the curve")
	}
	point := make([]byte, 1+2*size)
	point[0] = 4 // uncompressed
	copy(point[1+size-len(xb):1+size], xb)
	copy(point[1+2*size-len(yb):], yb)
	return ecdsa.ParseUncompressedPublicKey(curve, point)
}
