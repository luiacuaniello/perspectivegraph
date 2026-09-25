package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

const v2Secret = "s3cr3t"

// signedV2 builds a v2-signed ingest request, with optional edits applied AFTER signing.
func signedV2(t *testing.T, ts time.Time, target string, body []byte, after func(*http.Request)) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	u, _ := url.Parse(target)
	sig := SignV2(v2Secret, ts.Unix(), http.MethodPost, u.EscapedPath(), u.Query(), body)
	r.Header.Set(TimestampHeader, strconv.FormatInt(ts.Unix(), 10))
	r.Header.Set(SignatureV2Header, sig)
	if after != nil {
		after(r)
	}
	return r
}

func v2Verifier(now time.Time) (*HMACVerifier, http.Handler) {
	h := NewHMACVerifier(map[string]string{DefaultTenant: v2Secret}, 1<<20, nil)
	h.now = func() time.Time { return now }
	return h, h.Require(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
}

func status(h http.Handler, r *http.Request) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

// v2 binds a request to its moment, its endpoint and its parameters. v1 bound only the
// body: the commit a report counts against travels in the query, so a captured request
// could be replayed, or re-attributed to another commit, at will.
func TestV2SignatureBindsTimePathAndParameters(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	body := []byte(`{"results":[]}`)
	const target = "/ingest/trivy?slug=acme%2Fpayments&sha=abc123&pr=42"

	_, h := v2Verifier(now)
	if got := status(h, signedV2(t, now, target, body, nil)); got != http.StatusAccepted {
		t.Fatalf("a valid v2 request = %d", got)
	}
	if got := status(h, signedV2(t, now, target, body, nil)); got != http.StatusUnauthorized {
		t.Errorf("the same signature a second time = %d, want 401 (replay)", got)
	}
	for name, r := range map[string]*http.Request{
		// Each case has a timestamp of its own, so it is refused for what it changed and
		// not as a replay of the valid request above.
		"another commit": signedV2(t, now.Add(5*time.Second), target, body, func(r *http.Request) {
			r.URL.RawQuery = "slug=acme%2Fpayments&sha=0ther&pr=42"
		}),
		"another endpoint":     signedV2(t, now.Add(time.Second), target, body, func(r *http.Request) { r.URL.Path = "/ingest/events" }),
		"signed too long ago":  signedV2(t, now.Add(-6*time.Minute), target, body, nil),
		"signed in the future": signedV2(t, now.Add(6*time.Minute), target, body, nil),
		"no timestamp":         signedV2(t, now.Add(2*time.Second), target, body, func(r *http.Request) { r.Header.Del(TimestampHeader) }),
		"a wrong v2 beside a right v1": signedV2(t, now.Add(3*time.Second), target, body, func(r *http.Request) {
			r.Header.Set(SignatureV2Header, "v2=00")
			r.Header.Set(SignatureHeader, Sign(v2Secret, body))
		}),
	} {
		if got := status(h, r); got != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, got)
		}
	}
	// The query's order is the sender's business: the canonical form sorts it.
	reordered := signedV2(t, now.Add(4*time.Second), target, body, func(r *http.Request) {
		r.URL.RawQuery = "pr=42&sha=abc123&slug=acme%2Fpayments"
	})
	if got := status(h, reordered); got != http.StatusAccepted {
		t.Errorf("the same parameters in another order = %d, want 202", got)
	}
}

// v1 stays accepted until the operator turns it off - so no sender breaks on upgrade -
// and is refused once they do.
func TestV1IsAcceptedUntilTurnedOff(t *testing.T) {
	body := []byte(`{}`)
	v1 := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/ingest/events", bytes.NewReader(body))
		r.Header.Set(SignatureHeader, Sign(v2Secret, body))
		return r
	}
	hv, h := v2Verifier(time.Now())
	if got := status(h, v1()); got != http.StatusAccepted {
		t.Fatalf("v1 with the default = %d, want 202", got)
	}
	hv.WithAcceptV1(false)
	if got := status(h, v1()); got != http.StatusUnauthorized {
		t.Fatalf("v1 with INGEST_HMAC_ACCEPT_V1=false = %d, want 401", got)
	}
}
