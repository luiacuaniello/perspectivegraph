package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/internal/ingestion"
)

// engine stands in for the ingestion endpoint with the engine's own verifier in front -
// v1 refused, so only a correct v2 signature gets through - and records what reached the
// handler behind it. reply answers each request in turn; past the last, the last repeats.
func engine(t *testing.T, secrets map[string]string, reply ...int) (*httptest.Server, *[]*http.Request, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	var seen []*http.Request
	verifier := auth.NewHMACVerifier(secrets, ingestion.MaxBody, nil).WithAcceptV1(false)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1))
		seen = append(seen, r)
		status := reply[min(n, len(reply))-1]
		w.WriteHeader(status)
		if status == http.StatusAccepted {
			_, _ = io.WriteString(w, `{"accepted_events":3,"batch":"0123456789abcdef0123456789abcdef"}`)
		} else {
			_, _ = io.WriteString(w, "temporarily unavailable")
		}
	})
	srv := httptest.NewServer(verifier.Require(nil, h))
	t.Cleanup(srv.Close)
	return srv, &seen, &calls
}

func report(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The report reaches the handler behind the engine's verifier, with every attribution
// parameter: v2 covers the query, so a parameter added after signing would be refused.
func TestIngestSignsTheReportAsTheEngineVerifies(t *testing.T) {
	t.Setenv("INGEST_HMAC_SECRET", "s3cr3t")
	srv, seen, _ := engine(t, map[string]string{auth.DefaultTenant: "s3cr3t"}, http.StatusAccepted)
	var out bytes.Buffer
	err := runIngest([]string{"-url", srv.URL, "-slug", "acme/app", "-sha", "abc123", "-pr", "42", "-cluster", "prod-eu", "-snapshot", "cluster:prod-eu",
		"semgrep", report(t, `{"results":[]}`)}, nil, &out)
	if err != nil {
		t.Fatalf("an engine refusing v1 rejected the request: %v", err)
	}
	if len(*seen) != 1 {
		t.Fatalf("%d requests reached the handler, want 1", len(*seen))
	}
	r := (*seen)[0]
	if r.URL.Path != "/ingest/semgrep" {
		t.Errorf("path %q", r.URL.Path)
	}
	for k, want := range map[string]string{"slug": "acme/app", "sha": "abc123", "pr": "42", "cluster": "prod-eu", "snapshot": "cluster:prod-eu"} {
		if got := r.URL.Query().Get(k); got != want {
			t.Errorf("%s=%q, want %q", k, got, want)
		}
	}
	if r.Header.Get(auth.SignatureHeader) != "" {
		t.Error("a v1 signature was sent: it covers the body alone, so the request could be replayed without its v2 header")
	}
	if !strings.Contains(out.String(), "3 event(s) accepted (batch 0123456789abcdef0123456789abcdef)") {
		t.Errorf("output %q", out.String())
	}
}

// A per-tenant secret is chosen by X-Tenant: the request must carry it and be signed with
// that tenant's secret, not the default one.
func TestIngestSignsForTheTenantItNames(t *testing.T) {
	srv, seen, _ := engine(t, map[string]string{auth.DefaultTenant: "default-secret", "acme": "acme-secret"}, http.StatusAccepted)
	err := runIngest([]string{"-url", srv.URL, "-tenant", "acme", "-hmac-secret", "acme-secret", "trivy", report(t, `{"Results":[]}`)}, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := (*seen)[0].Header.Get(auth.TenantHeader); got != "acme" {
		t.Errorf("X-Tenant %q", got)
	}
}

// A 503 after the engine verified the request is retried - and re-signed, because the
// first signature was accepted once already and the same one again is a replay.
func TestIngestRetriesWithAFreshSignature(t *testing.T) {
	t.Setenv("INGEST_HMAC_SECRET", "s3cr3t")
	srv, seen, calls := engine(t, map[string]string{auth.DefaultTenant: "s3cr3t"}, http.StatusServiceUnavailable, http.StatusAccepted)
	if err := runIngest([]string{"-url", srv.URL, "trivy", report(t, `{"Results":[]}`)}, nil, io.Discard); err != nil {
		t.Fatalf("the retry was refused: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("%d attempts reached the handler, want 2", calls.Load())
	}
	if (*seen)[0].Header.Get(auth.SignatureV2Header) == (*seen)[1].Header.Get(auth.SignatureV2Header) {
		t.Error("the retry reused the first signature")
	}
}

// A refused signature is not retried: another attempt with the same secret is refused the
// same way, and the error says what to fix.
func TestIngestDoesNotRetryARefusal(t *testing.T) {
	t.Setenv("INGEST_HMAC_SECRET", "")
	t.Setenv("INGEST_HMAC_SECRET_FILE", "")
	var calls atomic.Int32
	verifier := auth.NewHMACVerifier(map[string]string{auth.DefaultTenant: "s3cr3t"}, ingestion.MaxBody, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		verifier.Require(nil, http.NotFoundHandler()).ServeHTTP(w, r)
	}))
	defer srv.Close()
	err := runIngest([]string{"-url", srv.URL, "trivy", report(t, `{"Results":[]}`)}, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "set INGEST_HMAC_SECRET") {
		t.Fatalf("err = %v, want a 401 that names INGEST_HMAC_SECRET", err)
	}
	if calls.Load() != 1 {
		t.Errorf("%d attempts, want 1", calls.Load())
	}
}

// The secret can live in a file instead of the environment, as the engine's own can.
func TestIngestReadsTheSecretFromAFile(t *testing.T) {
	t.Setenv("INGEST_HMAC_SECRET", "")
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INGEST_HMAC_SECRET_FILE", p)
	srv, _, _ := engine(t, map[string]string{auth.DefaultTenant: "from-a-file"}, http.StatusAccepted)
	if err := runIngest([]string{"-url", srv.URL, "trivy", report(t, `{"Results":[]}`)}, nil, io.Discard); err != nil {
		t.Fatalf("signed with the file's secret, refused: %v", err)
	}

	t.Setenv("INGEST_HMAC_SECRET_FILE", filepath.Join(t.TempDir(), "missing"))
	if err := runIngest([]string{"-url", srv.URL, "trivy", report(t, `{"Results":[]}`)}, nil, io.Discard); err == nil {
		t.Fatal("a secret file that cannot be read sent the report unsigned instead of failing")
	}
}

// "-" reads the report from stdin, so a scanner can be piped straight in.
func TestIngestReadsStdin(t *testing.T) {
	t.Setenv("INGEST_HMAC_SECRET", "s3cr3t")
	srv, seen, _ := engine(t, map[string]string{auth.DefaultTenant: "s3cr3t"}, http.StatusAccepted)
	if err := runIngest([]string{"-url", srv.URL, "k8s", "-"}, strings.NewReader(`{"items":[]}`), io.Discard); err != nil {
		t.Fatal(err)
	}
	if (*seen)[0].URL.Path != "/ingest/k8s" {
		t.Errorf("path %q", (*seen)[0].URL.Path)
	}
}

// A report the endpoint would refuse is refused here, before it is sent: over the size
// limit, or empty.
func TestIngestRefusesWhatTheEndpointWould(t *testing.T) {
	srv, _, calls := engine(t, map[string]string{auth.DefaultTenant: "s3cr3t"}, http.StatusAccepted)
	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, bytes.Repeat([]byte(" "), ingestion.MaxBody+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runIngest([]string{"-url", srv.URL, "-hmac-secret", "s3cr3t", "trivy", big}, nil, io.Discard); err == nil || !strings.Contains(err.Error(), "32 MiB") {
		t.Errorf("oversized report: err = %v", err)
	}
	if err := runIngest([]string{"-url", srv.URL, "-hmac-secret", "s3cr3t", "trivy", report(t, "  \n")}, nil, io.Discard); err == nil {
		t.Error("an empty report was sent")
	}
	if calls.Load() != 0 {
		t.Errorf("%d requests sent, want none", calls.Load())
	}
}
