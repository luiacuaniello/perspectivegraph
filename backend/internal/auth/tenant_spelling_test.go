package auth

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/audit"
)

// A tenant has one spelling past authentication: a token, an OIDC claim and an ingest
// signature that write it as "Acme-Corp" all hand the engine "acme_corp", the key every
// store reads it by. The verdicts used to be kept under the token's spelling while the
// analyzer and the KEV holdout used the normalized one, so for such a tenant the
// calibration trend and the dashboard each missed the other's.
func TestATokensTenantIsNormalized(t *testing.T) {
	ts := NewTokenStore("tok:admin:Acme-Corp,low:viewer:acme_corp")
	p, ok := authToken(ts, "tok")
	if !ok || p.Tenant != "acme_corp" {
		t.Fatalf("token tenant = %q (ok %v), want acme_corp", p.Tenant, ok)
	}
	if q, _ := authToken(ts, "low"); q.Tenant != p.Tenant {
		t.Errorf("two spellings of one tenant are two principals' tenants: %q and %q", p.Tenant, q.Tenant)
	}
	// The startup checks still see the names as written, to tell a case difference from two
	// names that become one tenant.
	if got := ts.Tenants(); len(got) != 2 || got[0] != "Acme-Corp" || got[1] != "acme_corp" {
		t.Errorf("Tenants() = %q, want the spellings as written", got)
	}
}

func TestAnIngestSignaturesTenantIsNormalized(t *testing.T) {
	now := time.Now()
	h := NewHMACVerifier(map[string]string{"Acme-Corp": v2Secret}, 1<<20, nil)
	h.now = func() time.Time { return now }
	var seen string
	handler := h.Require(audit.Nop{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = PrincipalFromContext(r.Context()).Tenant
		w.WriteHeader(http.StatusAccepted)
	}))
	for i, header := range []string{"Acme-Corp", "ACME-CORP", "acme_corp"} {
		seen = ""
		rec := httptest.NewRecorder()
		// A body of its own each time: a v2 signature is accepted once.
		body := []byte(`{"n":` + strconv.Itoa(i) + `}`)
		handler.ServeHTTP(rec, signedV2(t, now, "/ingest/trivy?repo=x", body, func(r *http.Request) {
			r.Header.Set(TenantHeader, header)
		}))
		if rec.Code != http.StatusAccepted {
			t.Errorf("X-Tenant %q: %d, want 202 - the secret is the tenant's however it is spelt", header, rec.Code)
			continue
		}
		if seen != "acme_corp" {
			t.Errorf("X-Tenant %q: the principal's tenant is %q, want acme_corp", header, seen)
		}
	}
}
