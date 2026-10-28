package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// A token that names no tenant used to be read as the default tenant's. With one tenant
// that is the only reading there is; with several, the default is a tenant like the others,
// and a subject the IdP did not place in one read its graph. Where several are configured,
// such a token is now refused - and one that names its tenant is taken as before.
func TestATokenWithoutATenantIsRefusedWhereSeveralAreServed(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "tenant-key"
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": kid,
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}})
	}))
	defer jwks.Close()

	token := func(tenant any) *http.Request {
		claims := jwt.MapClaims{"iss": "https://idp.example", "aud": "perspectivegraph", "sub": "bob",
			"role": "viewer", "exp": time.Now().Add(time.Hour).Unix()}
		if tenant != nil {
			claims["tenant"] = tenant
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		r.Header.Set("Authorization", "Bearer "+s)
		return r
	}
	authn := func(require bool) *JWTAuthenticator {
		return NewJWTAuthenticator(JWTConfig{JWKSURL: jwks.URL, Issuer: "https://idp.example",
			Audience: "perspectivegraph", RequireTenant: require})
	}

	for name, c := range map[string]struct {
		require    bool
		tenant     any
		ok         bool
		wantTenant string
	}{
		"one tenant, no claim":                  {require: false, tenant: nil, ok: true, wantTenant: DefaultTenant},
		"several, no claim":                     {require: true, tenant: nil, ok: false},
		"several, an empty claim":               {require: true, tenant: "", ok: false},
		"several, a claim that is not a string": {require: true, tenant: 42, ok: false},
		"several, the claim names a tenant":     {require: true, tenant: "acme", ok: true, wantTenant: "acme"},
		"several, the claim names the default":  {require: true, tenant: DefaultTenant, ok: true, wantTenant: DefaultTenant},
	} {
		t.Run(name, func(t *testing.T) {
			p, ok := authn(c.require).Authenticate(token(c.tenant))
			if ok != c.ok {
				t.Fatalf("authenticated = %v, want %v (principal %+v)", ok, c.ok, p)
			}
			if ok && p.Tenant != c.wantTenant {
				t.Errorf("tenant = %q, want %q", p.Tenant, c.wantTenant)
			}
		})
	}
}
