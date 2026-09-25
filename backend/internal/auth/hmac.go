package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/audit"
	"github.com/luiacuaniello/perspectivegraph/internal/clientip"
	"github.com/luiacuaniello/perspectivegraph/internal/metrics"
)

// SignatureHeader carries "sha256=<hex>"; TenantHeader selects the tenant whose
// secret to verify against (defaults to DefaultTenant).
const (
	SignatureHeader = "X-PerspectiveGraph-Signature"
	TenantHeader    = "X-Tenant"

	// SignatureV2Header carries "v2=<hex>" and TimestampHeader the unix seconds it was
	// signed at. See SignV2.
	SignatureV2Header = "X-PerspectiveGraph-Signature-V2"
	TimestampHeader   = "X-PerspectiveGraph-Timestamp"
)

// SignatureWindow is how far a v2 signature's timestamp may be from the server's clock,
// either way. Outside it the request is refused as stale; inside it a signature is
// accepted once.
const SignatureWindow = 5 * time.Minute

// SignV2 signs an ingest request: the timestamp, the method, the path, the query and the
// body, so a captured request cannot be sent again later, sent to another endpoint, or
// have its parameters changed. The v1 signature covers the body alone: the query - which
// carries the repository and commit a report is attributed to - could be rewritten
// freely, and the request replayed for ever.
//
// The query is canonical - keys sorted, each key's values sorted - so a client and the
// server agree however either one ordered it.
func SignV2(secret string, ts int64, method, path string, query url.Values, body []byte) string {
	bodySum := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v2\n" + strconv.FormatInt(ts, 10) + "\n" + strings.ToUpper(method) + "\n" + path + "\n" +
		canonicalQuery(query) + "\n" + hex.EncodeToString(bodySum[:])))
	return "v2=" + hex.EncodeToString(mac.Sum(nil))
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

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
	secrets  map[string]string // tenant -> secret
	maxBody  int64
	ips      *clientip.Resolver
	acceptV1 bool
	now      func() time.Time

	// seen holds the v2 signatures accepted inside the window, so each is accepted once.
	// Per process: a replica has not seen what another accepted, so across replicas a
	// replay inside the window is refused only by the replica that took the original.
	seenMu    sync.Mutex
	seen      map[string]time.Time
	seenSwept time.Time
	warnedV1  atomic.Bool
}

// ips resolves the address recorded in the audit trail. Nil trusts no proxy. v1
// signatures are accepted until WithAcceptV1(false).
func NewHMACVerifier(secrets map[string]string, maxBody int64, ips *clientip.Resolver) *HMACVerifier {
	return &HMACVerifier{secrets: secrets, maxBody: maxBody, ips: ips, acceptV1: true, now: time.Now,
		seen: map[string]time.Time{}}
}

// WithAcceptV1 decides whether a request signed only with v1 - the body alone - is still
// accepted (INGEST_HMAC_ACCEPT_V1). It is, by default, so every sender keeps working
// through an upgrade; turn it off once they all sign v2, and a captured request can no
// longer be replayed or re-attributed by stripping its v2 header.
func (h *HMACVerifier) WithAcceptV1(accept bool) *HMACVerifier {
	h.acceptV1 = accept
	return h
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
			metrics.AuthDenied.WithLabelValues("ingest", "unknown_tenant").Inc()
			rec.Record(r.Context(), "auth.deny", "hmac", "", tenant, map[string]any{"reason": "unknown tenant", "remote": h.ips.Of(r)})
			unauthorized(w, "unknown tenant")
			return
		}
		body, err := readAll(w, r, h.maxBody)
		if err != nil {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		deny := func(reason, msg string) {
			metrics.AuthDenied.WithLabelValues("ingest", reason).Inc()
			rec.Record(r.Context(), "auth.deny", "hmac", "", tenant, map[string]any{"reason": reason, "remote": h.ips.Of(r)})
			unauthorized(w, msg)
		}
		// v2 when the sender sent it; then it is the only signature that counts, so a
		// wrong one is not rescued by a v1 alongside.
		if sig := r.Header.Get(SignatureV2Header); sig != "" {
			if reason := h.verifyV2(secret, sig, r, body); reason != "" {
				deny(reason, "invalid "+SignatureV2Header+": "+v2Refusals[reason])
				return
			}
		} else {
			if !h.acceptV1 {
				deny("v1_refused", "sign with "+SignatureV2Header+" and "+TimestampHeader+
					": v1 signatures are not accepted here (INGEST_HMAC_ACCEPT_V1=false)")
				return
			}
			if !verify(secret, r.Header.Get(SignatureHeader), body) {
				deny("bad_signature", "invalid or missing "+SignatureHeader)
				return
			}
			if h.warnedV1.CompareAndSwap(false, true) {
				slog.Warn("ingest accepted a v1 HMAC signature, which covers the body only: a captured request "+
					"can be replayed or re-attributed to another commit. Update the sender to sign v2, then set "+
					"INGEST_HMAC_ACCEPT_V1=false", "path", r.URL.Path)
			}
			metrics.IngestSignatures.WithLabelValues("v1").Inc()
		}
		restoreBody(r, body)
		rec.Record(r.Context(), "ingest", "hmac", "", tenant, map[string]any{"path": r.URL.Path, "remote": h.ips.Of(r)})
		p := Principal{Subject: "hmac", Tenant: tenant}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// v2Refusals explains each reason verifyV2 can return. The reasons themselves are short
// and fixed, because they label perspectivegraph_auth_denied_total.
var v2Refusals = map[string]string{
	"missing_timestamp": "missing or malformed " + TimestampHeader,
	"stale_timestamp":   "timestamp outside the " + SignatureWindow.String() + " window of the server's clock",
	"bad_signature":     "signature does not match",
	"replayed":          "this signature was already used",
}

// verifyV2 checks a v2 signature and returns why it is refused, or "" to accept it.
func (h *HMACVerifier) verifyV2(secret, sig string, r *http.Request, body []byte) string {
	ts, err := strconv.ParseInt(r.Header.Get(TimestampHeader), 10, 64)
	if err != nil {
		return "missing_timestamp"
	}
	now := h.now()
	if d := now.Sub(time.Unix(ts, 0)); d > SignatureWindow || d < -SignatureWindow {
		return "stale_timestamp"
	}
	want := SignV2(secret, ts, r.Method, r.URL.EscapedPath(), r.URL.Query(), body)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return "bad_signature"
	}
	h.seenMu.Lock()
	defer h.seenMu.Unlock()
	if now.Sub(h.seenSwept) > time.Minute {
		for k, exp := range h.seen {
			if now.After(exp) {
				delete(h.seen, k)
			}
		}
		h.seenSwept = now
	}
	if _, dup := h.seen[sig]; dup {
		return "replayed"
	}
	h.seen[sig] = time.Unix(ts, 0).Add(SignatureWindow)
	metrics.IngestSignatures.WithLabelValues("v2").Inc()
	return ""
}
