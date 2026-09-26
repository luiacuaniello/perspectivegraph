package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A fake engine: it records which endpoints the gate called, answers /gate/impact with
// impact (or a plain 404 when nil - an engine older than 1.22), ingest with a batch-less
// 202, and prVerdict with an analysed, dated verdict.
type fakeEngine struct {
	mu     sync.Mutex
	calls  []string
	impact *gateVerdict
	query  string
	auth   string
}

func (f *fakeEngine) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		switch {
		case r.URL.Path == "/gate/impact":
			if f.impact == nil {
				http.NotFound(w, r) // the stdlib's text 404: no such route
				return
			}
			f.mu.Lock()
			f.query, f.auth = r.URL.RawQuery, r.Header.Get("Authorization")
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(f.impact)
		case strings.HasPrefix(r.URL.Path, "/ingest/"):
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"accepted_events":1}`))
		case r.URL.Path == "/graphql":
			at := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
			_, _ = w.Write([]byte(`{"data":{"prVerdict":{"analysed":true,"criticalPaths":2,"analysedAt":"` + at + `","paths":[]}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeEngine) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func diffOpts(srv *httptest.Server) serverOpts {
	return serverOpts{
		client: srv.Client(), api: srv.URL, ingest: srv.URL, token: "t0ken",
		source: "trivy", slug: "acme/payments", sha: "c0ffee", repo: "acme/payments",
		report: []byte(`{}`), attribution: "diff", timeout: 2 * time.Second, poll: 10 * time.Millisecond,
	}
}

// The default: the report goes to /gate/impact, the answer is the verdict, and nothing
// is ingested - a pull request's scan does not land in the live graph.
func TestTheGateComparesAndWritesNothing(t *testing.T) {
	f := &fakeEngine{impact: &gateVerdict{Attribution: "diff", Analysed: true, CriticalPaths: 1,
		Paths: []gatePath{{ID: "p", Change: "introduced"}}}}
	srv := f.server(t)
	v, err := serverVerdict(diffOpts(srv), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if v.Attribution != "diff" || v.CriticalPaths != 1 {
		t.Fatalf("verdict %+v", v)
	}
	if got := f.called(); len(got) != 1 || got[0] != "POST /gate/impact" {
		t.Errorf("calls = %v, want only POST /gate/impact", got)
	}
	if !strings.Contains(f.query, "slug=acme%2Fpayments") || !strings.Contains(f.query, "sha=c0ffee") || !strings.Contains(f.query, "source=trivy") {
		t.Errorf("query %q does not name the change", f.query)
	}
	if f.auth != "Bearer t0ken" {
		t.Errorf("authorization %q", f.auth)
	}
}

// -persist also records the report in the live graph - after the verdict, which was
// computed on the estate without it.
func TestTheGatePersistsAfterTheVerdictWhenAsked(t *testing.T) {
	f := &fakeEngine{impact: &gateVerdict{Attribution: "diff", Analysed: true}}
	srv := f.server(t)
	o := diffOpts(srv)
	o.persist = true
	if _, err := serverVerdict(o, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := f.called(); len(got) != 2 || got[0] != "POST /gate/impact" || got[1] != "POST /ingest/trivy" {
		t.Errorf("calls = %v, want the comparison, then the ingest", got)
	}
}

// An engine older than 1.22 has no /gate/impact: the gate falls back to the per-commit
// record - ingest, then prVerdict - and says so in the verdict.
func TestTheGateFallsBackOnAnOlderEngine(t *testing.T) {
	f := &fakeEngine{} // no impact: plain 404
	srv := f.server(t)
	var log bytes.Buffer
	v, err := serverVerdict(diffOpts(srv), &log)
	if err != nil {
		t.Fatal(err)
	}
	if v.Attribution != "commit" || !v.Analysed || v.CriticalPaths != 2 {
		t.Fatalf("verdict %+v, want the engine's per-commit record", v)
	}
	got := f.called()
	if len(got) < 3 || got[0] != "POST /gate/impact" || got[1] != "POST /ingest/trivy" || got[2] != "POST /graphql" {
		t.Errorf("calls = %v", got)
	}
	if !strings.Contains(log.String(), "predates POST /gate/impact") {
		t.Errorf("the fallback was silent: %q", log.String())
	}
}

// A 404 that is the engine's own answer - an unknown collector - is an error, not an old
// engine: falling back would ingest a report the engine cannot parse.
func TestAnEngineRefusalIsNotMistakenForAnOldEngine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"unknown collector: trivvy"}`))
	}))
	t.Cleanup(srv.Close)
	if _, err := serverVerdict(diffOpts(srv), io.Discard); err == nil || !strings.Contains(err.Error(), "unknown collector") {
		t.Fatalf("err = %v, want the engine's refusal", err)
	}
}

// With no report there is nothing to compare: the gate reads the engine's record of the
// commit, as a poll-only gate always did.
func TestAGateWithoutAReportReadsTheRecord(t *testing.T) {
	f := &fakeEngine{impact: &gateVerdict{Attribution: "diff"}}
	srv := f.server(t)
	o := diffOpts(srv)
	o.report = nil
	v, err := serverVerdict(o, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if v.Attribution != "commit" {
		t.Errorf("attribution %q, want commit", v.Attribution)
	}
	for _, c := range f.called() {
		if c != "POST /graphql" {
			t.Errorf("unexpected call %s: poll-only must not compare or ingest", c)
		}
	}
}

// Local mode, the same comparison: the base branch's scan is already what runs, so the
// pull request's identical scan opens nothing - while the per-commit rule blocks it.
func TestLocalModeComparesWithWhatRunsNow(t *testing.T) {
	o := baseOpts(t)
	o.reports = []reportSpec{trivySampleSpec(t)}
	o.baseReports = []reportSpec{trivySampleSpec(t)}

	diff, err := localVerdict(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Attribution != "diff" || !diff.Analysed || diff.CriticalPaths != 0 || diff.Preexisting == 0 {
		t.Fatalf("diff verdict %+v, want analysed, nothing opened, the existing route noted", diff)
	}

	o.attribution = "commit"
	commit, err := localVerdict(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if commit.Attribution != "commit" || commit.CriticalPaths == 0 {
		t.Fatalf("commit verdict %+v, want the route through the commit counted", commit)
	}
}

// Without the base branch's scan the estate knows none of the image's findings, so the
// routes they open count against the change - the honest reading of what was given.
func TestLocalModeWithoutABaseScanCountsTheScansRoutes(t *testing.T) {
	o := baseOpts(t)
	o.reports = []reportSpec{trivySampleSpec(t)}
	v, err := localVerdict(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if v.CriticalPaths == 0 || v.Paths[0].Change != "introduced" {
		t.Fatalf("verdict %+v, want the scan's route counted as introduced", v)
	}
}

func TestTheGateSaysWhyEachRouteCounts(t *testing.T) {
	var b bytes.Buffer
	printGateVerdict(&b, gateVerdict{Attribution: "diff", Analysed: true, Reachable: true, CriticalPaths: 3, Preexisting: 4,
		Paths: []gatePath{
			{Priority: 81, Change: "introduced", Nodes: []gateNode{{Name: "alb"}, {Name: "ledger"}}},
			{Priority: 60, Change: "worsened", Score: 0.62, PreviousScore: 0.18, Nodes: []gateNode{{Name: "alb"}, {Name: "admin"}}},
			{Priority: 40, Change: "introduced", Redacted: true},
		}}, "acme/payments", "c0ffee", 0)
	out := b.String()
	for _, want := range []string{
		"this change opens or worsens 3 critical attack path(s)",
		"[P81] new: alb -> ledger",
		"[P60] worse, 18% -> 62%: alb -> admin",
		"[P40] new: a route outside the applications this token may read",
		"4 existing route(s) run through the change's assets",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	b.Reset()
	printGateVerdict(&b, gateVerdict{Attribution: "diff", Analysed: true, Reachable: false}, "acme/payments", "c0ffee", 0)
	if !strings.Contains(b.String(), "opens or worsens no critical attack path") || !strings.Contains(b.String(), "can be reached from an attack seed") {
		t.Errorf("clean, unreachable change reads:\n%s", b.String())
	}
}

// When the engine already held the commit, the routes count per commit, and the verdict
// must not claim the change opened them.
func TestARecordedCommitIsNotSaidToOpenRoutes(t *testing.T) {
	var b bytes.Buffer
	printGateVerdict(&b, gateVerdict{Attribution: "diff", Analysed: true, Reachable: true, Recorded: true, CriticalPaths: 1,
		Paths: []gatePath{{Priority: 39, Change: "recorded", Nodes: []gateNode{{Name: "alb"}, {Name: "vault"}}}}}, "acme/payments", "c0ffee", 0)
	out := b.String()
	if strings.Contains(out, "opens or worsens") || !strings.Contains(out, "1 critical attack path(s) count against this change") ||
		!strings.Contains(out, "[P39] through this commit: alb -> vault") || !strings.Contains(out, "already held this commit") {
		t.Errorf("recorded verdict reads:\n%s", out)
	}
}
