package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/secwatch"
)

func TestRequireRoleLockout(t *testing.T) {
	ts := NewTokenStore("admin-tok:admin")
	guard := secwatch.New(2, time.Minute, time.Minute, func(string, int) {})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := RequireRole(ts, RoleViewer, audit.Nop{}, guard, next)

	call := func(token, remote string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.RemoteAddr = remote
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Two bad attempts from one IP (different source ports) → 401, and the 2nd
	// trips the threshold.
	if c := call("wrong", "10.0.0.9:1111"); c != http.StatusUnauthorized {
		t.Fatalf("1st bad attempt = %d, want 401", c)
	}
	if c := call("wrong", "10.0.0.9:2222"); c != http.StatusUnauthorized {
		t.Fatalf("2nd bad attempt = %d, want 401", c)
	}
	// Now that IP is locked - even a VALID token is refused with 429.
	if c := call("admin-tok", "10.0.0.9:3333"); c != http.StatusTooManyRequests {
		t.Fatalf("locked IP with valid token = %d, want 429", c)
	}
	// A different IP is unaffected.
	if c := call("admin-tok", "10.0.0.42:4444"); c != http.StatusOK {
		t.Fatalf("different IP = %d, want 200", c)
	}
}

// TestLockoutIgnoresAnonymousAndInsufficientRole pins that the brute-force lockout
// only counts *rejected credentials*: a flood of anonymous requests (no token) or
// of valid-token-but-insufficient-role requests must NOT lock the IP out - so a
// login-gated dashboard polling before sign-in can't trip the lockout on itself.
func TestLockoutIgnoresAnonymousAndInsufficientRole(t *testing.T) {
	ts := NewTokenStore("viewer-tok:viewer,admin-tok:admin")
	guard := secwatch.New(2, time.Minute, time.Minute, func(string, int) {})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := RequireRole(ts, RoleAdmin, audit.Nop{}, guard, next) // endpoint needs admin

	call := func(token, remote string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.RemoteAddr = remote
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Anonymous (no credential) flood, well over the threshold - must stay 401, never 429.
	for i := 0; i < 5; i++ {
		if c := call("", "10.1.0.1:1000"); c != http.StatusUnauthorized {
			t.Fatalf("anon #%d = %d, want 401 (never counted/locked)", i, c)
		}
	}
	// Valid token but insufficient role (viewer < admin) flood - also must not count.
	for i := 0; i < 5; i++ {
		if c := call("viewer-tok", "10.1.0.1:2000"); c != http.StatusUnauthorized {
			t.Fatalf("insufficient-role #%d = %d, want 401 (never counted/locked)", i, c)
		}
	}
	// The IP is NOT locked: a sufficient credential still gets through.
	if c := call("admin-tok", "10.1.0.1:3000"); c != http.StatusOK {
		t.Fatalf("IP must not be locked by anon/insufficient floods, got %d, want 200", c)
	}
}

func TestHMACPerTenant(t *testing.T) {
	v := NewHMACVerifier(map[string]string{"acme": "acme-secret", DefaultTenant: "default-secret"}, 1<<20)
	got := ""
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = PrincipalFromContext(r.Context()).Tenant
		w.WriteHeader(http.StatusAccepted)
	})
	h := v.Require(audit.Nop{}, next)
	body := `{"source":"trivy"}`

	// correct signature for acme + X-Tenant: acme → 202, principal tenant = acme
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ingest/trivy", strings.NewReader(body))
	req.Header.Set(TenantHeader, "acme")
	req.Header.Set(SignatureHeader, Sign("acme-secret", []byte(body)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || got != "acme" {
		t.Errorf("acme signed: code=%d tenant=%q, want 202/acme", rec.Code, got)
	}

	// acme's secret used for the default tenant → 401 (tenant isolation)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/ingest/trivy", strings.NewReader(body))
	req.Header.Set(SignatureHeader, Sign("acme-secret", []byte(body))) // no X-Tenant → default
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("cross-tenant secret: got %d, want 401", rec.Code)
	}

	// unknown tenant → 401
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/ingest/trivy", strings.NewReader(body))
	req.Header.Set(TenantHeader, "ghost")
	req.Header.Set(SignatureHeader, Sign("x", []byte(body)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown tenant: got %d, want 401", rec.Code)
	}
}

func authToken(ts *TokenStore, tok string) (Principal, bool) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return ts.Authenticate(r)
}

func TestTokenStoreRoleAndTenant(t *testing.T) {
	ts := NewTokenStore("read:viewer, admin:admin:globex, junk, bad:notarole")
	if p, ok := authToken(ts, "read"); !ok || p.Role != RoleViewer || p.Tenant != DefaultTenant {
		t.Errorf("read token = %+v ok=%v, want viewer/default", p, ok)
	}
	if p, ok := authToken(ts, "admin"); !ok || p.Role != RoleAdmin || p.Tenant != "globex" {
		t.Errorf("admin token = %+v ok=%v, want admin/globex", p, ok)
	}
	if _, ok := authToken(ts, "junk"); ok {
		t.Error("malformed entry (no role) should not authenticate")
	}
	if _, ok := authToken(ts, "bad"); ok {
		t.Error("entry with an unknown role should not authenticate")
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Tenant-Seen", PrincipalFromContext(r.Context()).Tenant)
		w.WriteHeader(http.StatusOK)
	})
	// admin token, admin required → ok, tenant globex on context
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Authorization", "Bearer admin")
	RequireRole(ts, RoleAdmin, audit.Nop{}, nil, next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Tenant-Seen") != "globex" {
		t.Errorf("admin: code=%d tenant=%q, want 200/globex", rec.Code, rec.Header().Get("X-Tenant-Seen"))
	}
	// viewer token, admin required → 401
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Authorization", "Bearer read")
	RequireRole(ts, RoleAdmin, audit.Nop{}, nil, next).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("viewer/admin: got %d, want 401", rec.Code)
	}
}

func TestTokenLifecycleHashingAndApps(t *testing.T) {
	secret := "s3cr3t-token"
	hash := sha256Hex(secret)
	// A hashed, tenant+app-scoped admin with a future expiry, plus an expired one.
	spec := "sha256$" + hash + ":admin:globex:2099-12-31:payments|web, old:viewer::2000-01-01"
	ts := NewTokenStore(spec)
	ts.now = func() time.Time { return time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC) }

	// Authenticates with the RAW secret (only the hash is in config) and carries
	// role, tenant, and the app allowlist.
	p, ok := authToken(ts, secret)
	if !ok {
		t.Fatal("hashed token should authenticate with the raw secret")
	}
	if p.Role != RoleAdmin || p.Tenant != "globex" {
		t.Errorf("principal = %+v, want admin/globex", p)
	}
	if len(p.Apps) != 2 || p.Apps[0] != "payments" || p.Apps[1] != "web" {
		t.Errorf("apps = %v, want [payments web]", p.Apps)
	}
	// The stored hash itself is not a usable credential.
	if _, ok := authToken(ts, "sha256$"+hash); ok {
		t.Error("the stored hash must not be accepted as a token")
	}
	// Expiry is enforced.
	if _, ok := authToken(ts, "old"); ok {
		t.Error("expired token (2000-01-01) must be rejected")
	}
	ts.now = func() time.Time { return time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, ok := authToken(ts, "old"); !ok {
		t.Error("token should be valid before its expiry date")
	}
}

func TestJWTAuthenticator(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key-1"

	// minimal JWKS endpoint serving the public key
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "kid": kid, "n": n, "e": e}},
		})
	}))
	defer jwks.Close()

	authn := NewJWTAuthenticator(JWTConfig{
		JWKSURL: jwks.URL, Issuer: "https://idp.example", Audience: "perspectivegraph",
	})
	if !authn.Enabled() {
		t.Fatal("JWT authenticator should be enabled with a JWKS URL")
	}

	mint := func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	good := mint(jwt.MapClaims{
		"iss": "https://idp.example", "aud": "perspectivegraph", "sub": "alice",
		"role": "operator", "tenant": "acme", "exp": time.Now().Add(time.Hour).Unix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+good)
	p, ok := authn.Authenticate(req)
	if !ok {
		t.Fatal("valid JWT should authenticate")
	}
	if p.Role != RoleOperator || p.Tenant != "acme" || p.Subject != "jwt:alice" {
		t.Errorf("principal = %+v, want operator/acme/jwt:alice", p)
	}

	// wrong audience → reject
	badAud := mint(jwt.MapClaims{
		"iss": "https://idp.example", "aud": "someone-else", "sub": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	req = httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+badAud)
	if _, ok := authn.Authenticate(req); ok {
		t.Error("JWT with wrong audience must be rejected")
	}

	// expired → reject
	expired := mint(jwt.MapClaims{
		"iss": "https://idp.example", "aud": "perspectivegraph", "sub": "alice",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	req = httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+expired)
	if _, ok := authn.Authenticate(req); ok {
		t.Error("expired JWT must be rejected")
	}
}

// TestJWKSRefetchOnKeyRotation pins the rotation behavior: an unknown kid (the
// IdP rotated signing keys) triggers a JWKS refetch so freshly-signed tokens keep
// working - but not within jwksMinRefetch of the last fetch, so a flood of bogus
// kids can't amplify into a JWKS-fetch storm.
func TestJWKSRefetchOnKeyRotation(t *testing.T) {
	type keyset struct {
		key *rsa.PrivateKey
		kid string
	}
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var cur atomic.Pointer[keyset]
	cur.Store(&keyset{keyA, "key-a"})

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ks := cur.Load()
		n := base64.RawURLEncoding.EncodeToString(ks.key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(ks.key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "kid": ks.kid, "n": n, "e": e}},
		})
	}))
	defer jwks.Close()

	authn := NewJWTAuthenticator(JWTConfig{JWKSURL: jwks.URL, Issuer: "https://idp.example", Audience: "perspectivegraph"})
	mint := func(key *rsa.PrivateKey, kid string) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": "https://idp.example", "aud": "perspectivegraph", "sub": "alice",
			"role": "viewer", "exp": time.Now().Add(time.Hour).Unix(),
		})
		tok.Header["kid"] = kid
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	authOK := func(raw string) bool {
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		_, ok := authn.Authenticate(req)
		return ok
	}

	// Key A authenticates and populates the cache.
	if !authOK(mint(keyA, "key-a")) {
		t.Fatal("token signed with the current key must authenticate")
	}
	// IdP rotates to key B. Within the rate-limit window the new kid isn't refetched.
	cur.Store(&keyset{keyB, "key-b"})
	if authOK(mint(keyB, "key-b")) {
		t.Error("within jwksMinRefetch, an unknown kid must NOT trigger a refetch (anti-spam)")
	}
	// After the window lapses, the unknown kid triggers a refetch and the rotated key works.
	authn.keys.mu.Lock()
	authn.keys.fetched = time.Now().Add(-2 * jwksMinRefetch)
	authn.keys.mu.Unlock()
	if !authOK(mint(keyB, "key-b")) {
		t.Error("after jwksMinRefetch, a rotated signing key must be picked up via refetch")
	}
}

func TestChainTriesEach(t *testing.T) {
	ts := NewTokenStore("tok:viewer")
	chain := Chain{ts, &JWTAuthenticator{cfg: JWTConfig{}}} // jwt disabled (no JWKS)
	if !chain.Enabled() {
		t.Fatal("chain should be enabled when any member is")
	}
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.Header.Set("Authorization", "Bearer tok")
	if p, ok := chain.Authenticate(req); !ok || p.Role != RoleViewer {
		t.Errorf("chain auth = %+v,%v, want viewer/true", p, ok)
	}
}
