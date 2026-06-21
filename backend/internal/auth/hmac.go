package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/luiacuaniello/perspectivegraph/internal/audit"
)

// SignatureHeader carries "sha256=<hex>"; TenantHeader selects the tenant whose
// secret to verify against (defaults to DefaultTenant).
const (
	SignatureHeader = "X-PerspectiveGraph-Signature"
	TenantHeader    = "X-Tenant"
)

// Sign returns the signature header value a sender must send for body+secret.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func verify(secret, header string, body []byte) bool {
	want, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	sig, err := hex.DecodeString(want)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(sig, mac.Sum(nil))
}

// HMACVerifier guards ingest webhooks with a per-tenant HMAC secret. A shared
// secret across tenants would let one tenant post into another's graph, so each
// tenant gets its own secret and the X-Tenant header selects it.
type HMACVerifier struct {
	secrets map[string]string // tenant -> secret
	maxBody int64
}

func NewHMACVerifier(secrets map[string]string, maxBody int64) *HMACVerifier {
	return &HMACVerifier{secrets: secrets, maxBody: maxBody}
}

func (h *HMACVerifier) Enabled() bool { return len(h.secrets) > 0 }

// Require verifies the body signature against the selected tenant's secret,
// restores the body, stamps the tenant principal on the context, and audits.
func (h *HMACVerifier) Require(rec audit.Recorder, next http.Handler) http.Handler {
	if rec == nil {
		rec = audit.Nop{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := r.Header.Get(TenantHeader)
		if tenant == "" {
			tenant = DefaultTenant
		}
		secret, ok := h.secrets[tenant]
		if !ok {
			rec.Record("auth.deny", "hmac", "", tenant, map[string]any{"reason": "unknown tenant", "remote": clientIP(r)})
			unauthorized(w, "unknown tenant")
			return
		}
		body, err := readAll(w, r, h.maxBody)
		if err != nil {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if !verify(secret, r.Header.Get(SignatureHeader), body) {
			rec.Record("auth.deny", "hmac", "", tenant, map[string]any{"reason": "bad signature", "remote": clientIP(r)})
			unauthorized(w, "invalid or missing "+SignatureHeader)
			return
		}
		restoreBody(r, body)
		rec.Record("ingest", "hmac", "", tenant, map[string]any{"path": r.URL.Path, "remote": clientIP(r)})
		p := Principal{Subject: "hmac", Tenant: tenant}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}
