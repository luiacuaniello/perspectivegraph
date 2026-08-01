package ingestion

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/auth"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// ── doubles ─────────────────────────────────────────────────────────────────

type capturingPublisher struct {
	got []ontology.Event
	err error
}

func (p *capturingPublisher) Publish(_ context.Context, ev ontology.Event) error {
	if p.err != nil {
		return p.err
	}
	p.got = append(p.got, ev)
	return nil
}

// fakeCollector stands in for a scanner parser (trivy, semgrep, …).
type fakeCollector struct {
	source   string
	err      error
	gotOpts  Options
	gotBody  string
	produces []ontology.Event
}

func (c *fakeCollector) Source() string { return c.source }
func (c *fakeCollector) Parse(r io.Reader, opts Options) ([]ontology.Event, error) {
	b, _ := io.ReadAll(r)
	c.gotBody, c.gotOpts = string(b), opts
	if c.err != nil {
		return nil, c.err
	}
	return c.produces, nil
}

func oneEvent(source string) []ontology.Event {
	return []ontology.Event{{
		Source: source,
		Nodes:  []ontology.Node{{ID: "n1", Label: ontology.LabelContainer, Name: "payments"}},
		Edges:  []ontology.Edge{{Type: ontology.EdgeHosts, From: "n1", To: "n2"}},
	}}
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ── the tenant boundary ─────────────────────────────────────────────────────

// The single most important property of this handler: the tenant an event lands in is
// taken from the AUTHENTICATED PRINCIPAL, never from the request body. If a caller
// could set it, any tenant could write into any other tenant's graph - which is exactly
// the isolation the product sells.
func TestTenantComesFromThePrincipalNotTheBody(t *testing.T) {
	pub := &capturingPublisher{}
	h := NewServer(pub).Handler()

	body, _ := json.Marshal(ontology.Event{Source: "attacker", Tenant: "victim-corp"})
	req := httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(string(body)))
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Tenant: "acme"}))

	if rec := do(h, req); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if len(pub.got) != 1 {
		t.Fatalf("published %d events, want 1", len(pub.got))
	}
	if pub.got[0].Tenant != "acme" {
		t.Fatalf("event landed in tenant %q - the body overrode the principal", pub.got[0].Tenant)
	}
}

// ── /ingest/{source} ────────────────────────────────────────────────────────

func TestUnknownCollectorIs404(t *testing.T) {
	h := NewServer(&capturingPublisher{}).Handler()
	rec := do(h, httptest.NewRequest(http.MethodPost, "/ingest/nosuchtool", strings.NewReader("{}")))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "nosuchtool") {
		t.Errorf("the 404 does not name the collector: %s", rec.Body)
	}
}

func TestToolIngestPassesBodyAndPRContextToTheCollector(t *testing.T) {
	c := &fakeCollector{source: "trivy", produces: oneEvent("trivy")}
	pub := &capturingPublisher{}
	h := NewServer(pub, c).Handler()

	req := httptest.NewRequest(http.MethodPost,
		"/ingest/trivy?repo=github.com/acme/api&slug=acme/api&sha=deadbeef&pr=42",
		strings.NewReader(`{"Results":[]}`))
	if rec := do(h, req); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if c.gotBody != `{"Results":[]}` {
		t.Errorf("collector saw body %q", c.gotBody)
	}
	if c.gotOpts.RepoSlug != "acme/api" || c.gotOpts.CommitSHA != "deadbeef" || c.gotOpts.PRNumber != 42 {
		t.Errorf("collector saw opts %+v", c.gotOpts)
	}
	if len(pub.got) != 1 {
		t.Errorf("published %d events, want 1", len(pub.got))
	}
}

// A non-numeric ?pr= is a caller mistake, not a reason to reject the scan: the report
// still carries findings worth ingesting, it just cannot be attached to a PR.
func TestNonNumericPRIsIgnoredRatherThanFatal(t *testing.T) {
	c := &fakeCollector{source: "trivy", produces: oneEvent("trivy")}
	h := NewServer(&capturingPublisher{}, c).Handler()
	req := httptest.NewRequest(http.MethodPost, "/ingest/trivy?pr=not-a-number", strings.NewReader("{}"))
	if rec := do(h, req); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d, want the scan accepted anyway", rec.Code)
	}
	if c.gotOpts.PRNumber != 0 {
		t.Errorf("PRNumber = %d, want 0", c.gotOpts.PRNumber)
	}
}

// A parser rejecting a malformed report is the caller's fault (400), and the reason has
// to reach them or they cannot fix their scanner invocation.
func TestCollectorParseErrorIs400WithTheReason(t *testing.T) {
	c := &fakeCollector{source: "trivy", err: errors.New("unexpected schema version 9")}
	h := NewServer(&capturingPublisher{}, c).Handler()
	rec := do(h, httptest.NewRequest(http.MethodPost, "/ingest/trivy", strings.NewReader("{}")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "schema version 9") {
		t.Errorf("the 400 hides the parser's reason: %s", rec.Body)
	}
}

// ── /ingest/events ──────────────────────────────────────────────────────────

func TestEventsAcceptsASingleObjectOrAnArray(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"single object", `{"source":"custom","nodes":[],"edges":[]}`, 1},
		{"array", `[{"source":"a"},{"source":"b"}]`, 2},
		{"empty array", `[]`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub := &capturingPublisher{}
			h := NewServer(pub).Handler()
			rec := do(h, httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(tc.body)))
			if rec.Code != http.StatusAccepted {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			if len(pub.got) != tc.want {
				t.Fatalf("published %d events, want %d", len(pub.got), tc.want)
			}
		})
	}
}

func TestEventsRejectsABodyThatIsNeither(t *testing.T) {
	for _, body := range []string{`"just a string"`, `{`, ``, `12`} {
		pub := &capturingPublisher{}
		h := NewServer(pub).Handler()
		rec := do(h, httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status %d, want 400", body, rec.Code)
		}
		if len(pub.got) != 0 {
			t.Errorf("body %q: published %d events despite being rejected", body, len(pub.got))
		}
	}
}

// The accepted response is what a CI step reads to know the scan landed, so the counts
// have to be real rather than an echo of the request.
func TestAcceptedResponseReportsWhatWasIngested(t *testing.T) {
	h := NewServer(&capturingPublisher{}, &fakeCollector{source: "trivy", produces: oneEvent("trivy")}).Handler()
	rec := do(h, httptest.NewRequest(http.MethodPost, "/ingest/trivy", strings.NewReader("{}")))

	var got struct {
		AcceptedEvents int `json:"accepted_events"`
		Nodes          int `json:"nodes"`
		Edges          int `json:"edges"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body)
	}
	if got.AcceptedEvents != 1 || got.Nodes != 1 || got.Edges != 1 {
		t.Errorf("counts %+v, want 1/1/1", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type %q", ct)
	}
}

// A bus that will not take the event must not be reported to the caller as accepted -
// the scan would be silently lost and CI would go green on nothing.
func TestPublishFailureIs502AndNotAccepted(t *testing.T) {
	pub := &capturingPublisher{err: errors.New("nats: no servers available")}
	h := NewServer(pub, &fakeCollector{source: "trivy", produces: oneEvent("trivy")}).Handler()
	rec := do(h, httptest.NewRequest(http.MethodPost, "/ingest/trivy", strings.NewReader("{}")))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
}

// A client that hangs up mid-ingest is not a server error: writing a 502 into a dead
// connection only pollutes the logs and the metrics.
func TestClientCancellationIsNotReportedAsAFailure(t *testing.T) {
	pub := &capturingPublisher{err: context.Canceled}
	h := NewServer(pub, &fakeCollector{source: "trivy", produces: oneEvent("trivy")}).Handler()
	rec := do(h, httptest.NewRequest(http.MethodPost, "/ingest/trivy", strings.NewReader("{}")))
	if rec.Code == http.StatusBadGateway {
		t.Errorf("a cancelled client produced a 502")
	}
}

// ── open endpoints ──────────────────────────────────────────────────────────

func TestHealthzIsOpen(t *testing.T) {
	h := NewServer(&capturingPublisher{}).Handler()
	rec := do(h, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz: %d %q", rec.Code, rec.Body)
	}
}

func TestConnectorsServesAnEmptyListWithoutAProvider(t *testing.T) {
	h := NewServer(&capturingPublisher{}).Handler()
	rec := do(h, httptest.NewRequest(http.MethodGet, "/connectors", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("body %q, want an empty JSON array", got)
	}
}

func TestConnectorsServesTheProvidersSnapshot(t *testing.T) {
	h := NewServer(&capturingPublisher{}).
		WithConnectorStatus(func() any { return []map[string]any{{"source": "aws", "last_error": ""}} }).
		Handler()
	rec := do(h, httptest.NewRequest(http.MethodGet, "/connectors", nil))
	if !strings.Contains(rec.Body.String(), `"source":"aws"`) {
		t.Errorf("body %q does not carry the snapshot", rec.Body)
	}
}

// A provider that returns nil must still produce valid JSON, not "null", so a dashboard
// polling it does not have to special-case the empty case.
func TestConnectorsHandlesANilSnapshot(t *testing.T) {
	h := NewServer(&capturingPublisher{}).WithConnectorStatus(func() any { return nil }).Handler()
	rec := do(h, httptest.NewRequest(http.MethodGet, "/connectors", nil))
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("body %q, want []", got)
	}
}

// ── wiring ──────────────────────────────────────────────────────────────────

func TestCollectorsAreRegisteredBySource(t *testing.T) {
	s := NewServer(&capturingPublisher{}, &fakeCollector{source: "trivy"}, &fakeCollector{source: "semgrep"})
	if len(s.collectors) != 2 || s.collectors["trivy"] == nil || s.collectors["semgrep"] == nil {
		t.Fatalf("collectors registered: %v", s.collectors)
	}
}

// The chaining setters must return the server, or `NewServer(...).WithX().Handler()`
// silently drops configuration.
func TestOptionSettersChain(t *testing.T) {
	s := NewServer(&capturingPublisher{})
	if s.WithRateLimit(nil) != s || s.WithHMAC(nil) != s || s.WithAudit(nil) != s || s.WithConnectorStatus(nil) != s {
		t.Fatal("an option setter did not return the server")
	}
	if s.audit == nil {
		t.Error("WithAudit(nil) cleared the no-op recorder, so audit calls would panic")
	}
}
