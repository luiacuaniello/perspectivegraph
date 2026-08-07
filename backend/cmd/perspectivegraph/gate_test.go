package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
)

// verdictServer serves prVerdict answers from a script, one per call, repeating the last.
func verdictServer(t *testing.T, script ...gateVerdict) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1)) - 1
		if n >= len(script) {
			n = len(script) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"prVerdict": script[n]},
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// THE false negative this gate exists to prevent, in its subtlest form.
//
// `analysed` is answered from the graph and `criticalPaths` from the last analyzer pass.
// Straight after ingest the commit is in the graph but the paths still describe the estate
// as it was before it arrived - so the engine truthfully answers "analysed: true,
// criticalPaths: 0" about a commit that has one. Accepting that first answer would pass
// the build. The gate must keep waiting until a pass ran after its own ingest.
func TestGateRejectsAVerdictOlderThanItsOwnIngest(t *testing.T) {
	floor := time.Now().UTC()
	stale := gateVerdict{Analysed: true, CriticalPaths: 0, AnalysedAt: rfc(floor.Add(-time.Minute))}
	fresh := gateVerdict{Analysed: true, CriticalPaths: 2, AnalysedAt: rfc(floor.Add(time.Second))}

	srv, calls := verdictServer(t, stale, stale, fresh)
	got, err := waitForVerdict(srv.Client(), srv.URL, "", "acme/payments", "abc123", floor, 5*time.Second, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	if got.CriticalPaths != 2 {
		t.Fatalf("criticalPaths = %d, want 2: the gate accepted a verdict computed before its own ingest and would have passed the build",
			got.CriticalPaths)
	}
	if calls.Load() < 3 {
		t.Errorf("polled %d times, want at least 3 - it did not wait for a fresh pass", calls.Load())
	}
}

// Poll-only mode has no floor: the caller is asserting that ingestion already happened.
// This must stay true, because on a steady graph the analyzer skips recomputing for up to
// ten ticks, and a floor would time out on a verdict that was already correct - turning a
// clean build red for no reason.
func TestGateAcceptsAnyVerdictWhenItDidNotIngest(t *testing.T) {
	old := gateVerdict{Analysed: true, CriticalPaths: 1, AnalysedAt: rfc(time.Now().Add(-time.Hour))}
	srv, calls := verdictServer(t, old)

	got, err := waitForVerdict(srv.Client(), srv.URL, "", "acme/payments", "abc123", time.Time{}, 5*time.Second, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Analysed || got.CriticalPaths != 1 {
		t.Fatalf("got %+v, want the verdict as served", got)
	}
	if calls.Load() != 1 {
		t.Errorf("polled %d times, want 1", calls.Load())
	}
}

// An engine that never answered told the gate exactly as much as one that never saw the
// commit, so a timeout has to arrive at the caller as UNKNOWN. Reporting the last-seen
// `analysed: true` would turn "we ran out of time" into a pass.
func TestGateTimeoutReportsUnknownNotClean(t *testing.T) {
	stale := gateVerdict{Analysed: true, CriticalPaths: 0, AnalysedAt: rfc(time.Now().Add(-time.Hour))}
	srv, _ := verdictServer(t, stale)

	got, err := waitForVerdict(srv.Client(), srv.URL, "", "acme/payments", "abc123", time.Now(), 30*time.Millisecond, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got.Analysed {
		t.Fatal("a timeout was reported as analysed, which the caller would exit 0 on")
	}
}

// A verdict that will not say when it was computed cannot be checked for freshness, so it
// counts as stale. The gate then waits and reports UNKNOWN - loud and wrong-way-safe,
// rather than quiet and wrong.
func TestGateTreatsAnUndatedVerdictAsStale(t *testing.T) {
	for name, at := range map[string]string{"empty": "", "not a time": "yesterday"} {
		t.Run(name, func(t *testing.T) {
			v := gateVerdict{Analysed: true, AnalysedAt: at}
			if verdictIsFresh(v, time.Now().Add(-time.Hour)) {
				t.Error("an undated verdict was accepted as fresh")
			}
		})
	}
}

// The stamping contract: unless slug and sha reach the ingest webhook, nothing in the
// graph carries the commit and every later verdict is UNKNOWN. This is also the HMAC
// path, since a signature computed over the wrong bytes fails closed at the webhook.
func TestGatePostsPRContextAndSignsTheBody(t *testing.T) {
	const secret = "shared-secret"
	body := []byte(`{"Results":[]}`)

	var gotQuery, gotSig, gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		gotSig = r.Header.Get(auth.SignatureHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	err := postGateReport(srv.Client(), srv.URL, "trivy", "acme/payments", "abc123", "acme/payments", 42, "", secret, body)
	if err != nil {
		t.Fatal(err)
	}

	if gotPath != "/ingest/trivy" {
		t.Errorf("path = %q, want /ingest/trivy", gotPath)
	}
	for _, want := range []string{"slug=acme%2Fpayments", "sha=abc123", "pr=42"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q is missing %q, so the asset would not carry the commit", gotQuery, want)
		}
	}
	if !bytes.Equal(gotBody, body) {
		t.Errorf("body was altered in transit: %q", gotBody)
	}
	if want := auth.Sign(secret, body); gotSig != want {
		t.Errorf("signature = %q, want %q", gotSig, want)
	}
}

// No secret configured means no signature header at all, rather than a header signed with
// the empty string - which a webhook with HMAC on would accept from anyone.
func TestGateSendsNoSignatureWithoutASecret(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header[http.CanonicalHeaderKey(auth.SignatureHeader)]
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	if err := postGateReport(srv.Client(), srv.URL, "trivy", "s", "c", "", 0, "", "", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("sent a signature header with no secret configured")
	}
}

// A webhook that rejected the report must stop the gate, not leave it polling for a
// verdict about a commit whose scan never arrived - the timeout would eventually say
// UNKNOWN, but hours later and without naming the cause.
func TestGateFailsWhenIngestIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad signature"))
	}))
	defer srv.Close()

	err := postGateReport(srv.Client(), srv.URL, "trivy", "s", "c", "", 0, "", "x", []byte("{}"))
	if err == nil {
		t.Fatal("a rejected ingest was reported as success")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "bad signature") {
		t.Errorf("the error hides what the webhook said: %v", err)
	}
}

// The output is what an engineer reads at 3pm on a red build. UNKNOWN in particular must
// never be phrased in a way that can be skimmed as a pass.
func TestGateOutputNamesWhatItBlockedOn(t *testing.T) {
	v := gateVerdict{
		Analysed:      true,
		CriticalPaths: 1,
		Paths: []gatePath{{
			ID: "p1", Priority: 91,
			Nodes: []gateNode{{Name: "edge-alb"}, {Name: "payments-db"}},
		}},
	}

	var buf bytes.Buffer
	printGateVerdict(&buf, v, "acme/payments", "abc123def456", 0)
	out := buf.String()
	if !strings.Contains(out, "BLOCKED") {
		t.Errorf("no verdict word in the output: %q", out)
	}
	if !strings.Contains(out, "edge-alb -> payments-db") {
		t.Errorf("the blocking route is not named, so the engineer has to go hunting: %q", out)
	}

	buf.Reset()
	printGateVerdict(&buf, gateVerdict{Analysed: false}, "acme/payments", "abc123def456", 0)
	unknown := buf.String()
	if !strings.Contains(unknown, "UNKNOWN") {
		t.Errorf("the never-analysed case is not labelled UNKNOWN: %q", unknown)
	}
	if !strings.Contains(unknown, "NOT a clean result") {
		t.Errorf("the UNKNOWN output does not say it is not a pass, which is the one thing it must say: %q", unknown)
	}
}
