package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

// An identity provider that signs with EC keys - ES256 is the default of several - could
// not sign anyone in: only RSA keys were read from its JWKS. The algorithm must also match
// the key it names, curve included, so a token cannot pick a verification the key was
// never meant for.
func TestJWTAcceptsECKeysAndMatchesAlgorithmToKey(t *testing.T) {
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	pad := func(n *big.Int, size int) []byte { b := make([]byte, size); n.FillBytes(b); return b }

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "EC", "kid": "ec256", "crv": "P-256", "x": b64(pad(ec256.X, 32)), "y": b64(pad(ec256.Y, 32))},
			{"kty": "EC", "kid": "ec384", "crv": "P-384", "x": b64(pad(ec384.X, 48)), "y": b64(pad(ec384.Y, 48))},
			{"kty": "EC", "kid": "offcurve", "crv": "P-256", "x": b64(pad(big.NewInt(1), 32)), "y": b64(pad(big.NewInt(2), 32))},
			{"kty": "RSA", "kid": "rsa", "n": b64(rsaKey.N.Bytes()), "e": b64(big.NewInt(int64(rsaKey.E)).Bytes())},
		}})
	}))
	defer jwks.Close()
	authn := NewJWTAuthenticator(JWTConfig{JWKSURL: jwks.URL, Issuer: "https://idp.example", Audience: "perspectivegraph"})

	claims := jwt.MapClaims{"iss": "https://idp.example", "aud": "perspectivegraph", "sub": "bob",
		"role": "viewer", "exp": time.Now().Add(time.Hour).Unix()}
	sign := func(m jwt.SigningMethod, kid string, key any) string {
		tok := jwt.NewWithClaims(m, claims)
		tok.Header["kid"] = kid
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ok := func(tok string) bool {
		r := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		_, ok := authn.Authenticate(r)
		return ok
	}

	if !ok(sign(jwt.SigningMethodES256, "ec256", ec256)) {
		t.Error("an ES256 token from a P-256 JWKS key was refused")
	}
	if !ok(sign(jwt.SigningMethodES384, "ec384", ec384)) {
		t.Error("an ES384 token from a P-384 JWKS key was refused")
	}
	if !ok(sign(jwt.SigningMethodRS256, "rsa", rsaKey)) {
		t.Error("RSA tokens stopped working")
	}
	if ok(sign(jwt.SigningMethodES256, "ec384", ec256)) {
		t.Error("an ES256 token was verified against a P-384 key")
	}
	if ok(sign(jwt.SigningMethodRS256, "ec256", rsaKey)) {
		t.Error("an RS256 token was accepted naming an EC key")
	}
	if ok(sign(jwt.SigningMethodES256, "offcurve", ec256)) {
		t.Error("a JWKS key off its curve was used")
	}
}
