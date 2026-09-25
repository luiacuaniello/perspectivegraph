package main

import (
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

// The gate learns its batch from the ingest response, and an engine too old to send one
// leaves it empty - the gate then behaves as it always did.
func TestPostGateReportReturnsTheBatch(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"tracked":      {`{"accepted_events":1,"batch":"0123456789abcdef0123456789abcdef","messages":4}`, "0123456789abcdef0123456789abcdef"},
		"older engine": {`{"accepted_events":1,"nodes":3,"edges":2}`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusAccepted)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			got, err := postGateReport(srv.Client(), srv.URL, "trivy", "s", "c", "", 0, "", "", []byte("{}"))
			if err != nil || got != tc.want {
				t.Fatalf("batch = %q, err %v; want %q", got, err, tc.want)
			}
		})
	}
}

// The gate waits for the last message of its report, and its freshness floor becomes
// that moment: a pass that ran after the post but before the last chunk landed saw part
// of the report, and its verdict is stale.
func TestTheGateWaitsForItsWholeReport(t *testing.T) {
	applied := time.Date(2026, 9, 25, 10, 0, 30, 0, time.UTC)
	var polls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "ingestBatch") {
			http.Error(w, "unexpected query", http.StatusBadRequest)
			return
		}
		b := map[string]any{"complete": false, "appliedAt": nil}
		if polls.Add(1) >= 3 {
			b = map[string]any{"complete": true, "appliedAt": applied.Format(time.RFC3339Nano)}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ingestBatch": b}})
	}))
	defer srv.Close()

	at, done, err := waitForBatch(srv.Client(), srv.URL, "", "0123456789abcdef0123456789abcdef", time.Now().Add(10*time.Second), 10*time.Millisecond)
	if err != nil || !done || !at.Equal(applied) {
		t.Fatalf("at=%v done=%v err=%v; want the batch complete at %v", at, done, err, applied)
	}
	if polls.Load() < 3 {
		t.Errorf("returned after %d polls, before the batch was complete", polls.Load())
	}
	early := gateVerdict{Analysed: true, AnalysedAt: applied.Add(-5 * time.Second).Format(time.RFC3339Nano)}
	if verdictIsFresh(early, at) {
		t.Error("a verdict from a pass before the last chunk landed was taken as fresh")
	}
	late := gateVerdict{Analysed: true, AnalysedAt: applied.Add(5 * time.Second).Format(time.RFC3339Nano)}
	if !verdictIsFresh(late, at) {
		t.Error("a verdict from a pass after the whole report landed was refused")
	}
}

// A batch that never completes is not waited on for ever, and is not reported complete.
func TestTheGateGivesUpOnABatchThatNeverCompletes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"ingestBatch":{"complete":false}}}`)
	}))
	defer srv.Close()
	_, done, err := waitForBatch(srv.Client(), srv.URL, "", "0123456789abcdef0123456789abcdef", time.Now().Add(100*time.Millisecond), 20*time.Millisecond)
	if err != nil || done {
		t.Fatalf("done=%v err=%v; want not done, no error", done, err)
	}
}

// The gate signs v2 exactly as the engine verifies it: its reports are accepted by an
// engine that refuses v1 - including the commit parameters, which v2 covers.
func TestTheGateSignsV2AsTheEngineVerifies(t *testing.T) {
	const secret = "s3cr3t"
	accepted := false
	verifier := auth.NewHMACVerifier(map[string]string{auth.DefaultTenant: secret}, 1<<20, nil).WithAcceptV1(false)
	srv := httptest.NewServer(verifier.Require(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		accepted = true
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{}`)
	})))
	defer srv.Close()
	if _, err := postGateReport(srv.Client(), srv.URL, "trivy", "acme/payments", "abc123", "acme/payments", 42, "", secret, []byte(`{"Results":[]}`)); err != nil {
		t.Fatalf("an engine refusing v1 rejected the gate: %v", err)
	}
	if !accepted {
		t.Fatal("the report never reached the handler")
	}
}
