package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeEngine stands in for the GraphQL API the tools query. It records the last query
// so a test can assert what the tool actually asked for - the tools exist to put the
// right question to the engine on a model's behalf, so the question is the contract.
type fakeEngine struct {
	srv       *httptest.Server
	lastQuery string
	lastAuth  string
	data      string // the "data" object, verbatim
	status    int
	errors    string // a GraphQL "errors" array, verbatim
}

func newFakeEngine(t *testing.T, data string) *fakeEngine {
	t.Helper()
	f := &fakeEngine{data: data, status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.lastQuery, f.lastAuth = body.Query, r.Header.Get("Authorization")
		w.WriteHeader(f.status)
		if f.errors != "" {
			_, _ = w.Write([]byte(`{"errors":` + f.errors + `}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":` + f.data + `}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEngine) api(token string) *API { return NewAPI(f.srv.URL, token) }

// toolByName finds a tool the way the JSON-RPC layer does.
func toolByName(t *testing.T, api *API, name string) Tool {
	t.Helper()
	for _, tl := range Tools(api) {
		if tl.Name == name {
			return tl
		}
	}
	t.Fatalf("tool %q is not registered", name)
	return Tool{}
}

func callTool(t *testing.T, api *API, name string, args map[string]any) (string, error) {
	t.Helper()
	return toolByName(t, api, name).Call(context.Background(), args)
}

const onePath = `{"attackPaths":[
  {"id":"p1","score":0.55,"priority":60,"priorityLabel":"P2","runtimeConfirmed":true,
   "nodes":[{"name":"edge-alb","label":"LoadBalancer","internetExposed":true},
            {"name":"payments-admin","label":"IAM_Role","crownJewel":true}],
   "steps":[{"edgeType":"EXPOSES","from":"edge-alb","to":"payments-admin","probability":0.9,"weightBasis":"epss"}],
   "remediations":[{"title":"Scope down the role","kind":"terraform"}]}]}`

// ── explain_attack_path ─────────────────────────────────────────────────────

func TestExplainAttackPathReturnsTheRequestedRoute(t *testing.T) {
	f := newFakeEngine(t, onePath)
	out, err := callTool(t, f.api(""), "explain_attack_path", map[string]any{"path_id": "p1"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(out, `"id":"p1"`) || !strings.Contains(out, "weightBasis") {
		t.Errorf("output does not carry the route and its hop provenance: %s", out)
	}
}

// The tool asks for the hop provenance on purpose: a model must be able to tell the
// model's own evidence (kev/epss/runtime) from its estimates (cvss/heuristic). Dropping
// those fields from the query would silently make every hop look equally certain.
func TestExplainAttackPathAsksForHopProvenance(t *testing.T) {
	f := newFakeEngine(t, onePath)
	if _, err := callTool(t, f.api(""), "explain_attack_path", map[string]any{"path_id": "p1"}); err != nil {
		t.Fatalf("call: %v", err)
	}
	for _, field := range []string{"weightBasis", "confidenceLabel", "attack", "steps"} {
		if !strings.Contains(f.lastQuery, field) {
			t.Errorf("the query does not request %q, so the model loses that signal", field)
		}
	}
}

// A missing path_id must be refused with an instruction the model can act on, rather
// than silently returning the whole board.
func TestExplainAttackPathRequiresAPathID(t *testing.T) {
	f := newFakeEngine(t, onePath)
	_, err := callTool(t, f.api(""), "explain_attack_path", map[string]any{})
	if err == nil {
		t.Fatal("a missing path_id was accepted")
	}
	if !strings.Contains(err.Error(), "list_attack_paths") {
		t.Errorf("the error does not tell the model where to get one: %v", err)
	}
}

func TestExplainAttackPathReportsAnUnknownID(t *testing.T) {
	f := newFakeEngine(t, onePath)
	out, err := callTool(t, f.api(""), "explain_attack_path", map[string]any{"path_id": "nope"})
	if err == nil && !strings.Contains(strings.ToLower(out), "nope") && out != "" {
		t.Errorf("an unknown id neither errored nor said so: %q", out)
	}
}

// ── the remaining tools ─────────────────────────────────────────────────────

func TestListFixesQueriesTheRemediationPlan(t *testing.T) {
	f := newFakeEngine(t, `{"remediationPlan":[{"title":"Scope down IAM role","kind":"terraform","pathCount":4,"coveragePct":0.31}]}`)
	out, err := callTool(t, f.api(""), "list_fixes", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(out, "Scope down IAM role") {
		t.Errorf("output lost the fix: %s", out)
	}
	if !strings.Contains(f.lastQuery, "remediationPlan") {
		t.Errorf("list_fixes did not ask for the remediation plan: %s", f.lastQuery)
	}
}

func TestSimulateFixAsksWhatIf(t *testing.T) {
	f := newFakeEngine(t, `{"whatIf":{"before":[{"id":"p1"}],"after":[],"removedEdges":1,"riskReduction":0.4}}`)
	out, err := callTool(t, f.api(""), "simulate_fix", map[string]any{
		"cuts": []any{map[string]any{"from": "edge-alb", "to": "payments", "type": "EXPOSES"}},
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(f.lastQuery, "whatIf") {
		t.Errorf("simulate_fix did not use the whatIf resolver: %s", f.lastQuery)
	}
	if !strings.Contains(out, "riskReduction") && !strings.Contains(out, "removedEdges") {
		t.Errorf("output does not report the effect of the cut: %s", out)
	}
}

func TestSearchAssetsPassesTheQueryThrough(t *testing.T) {
	f := newFakeEngine(t, `{"search":[{"id":"n1","name":"payments","label":"Container"}]}`)
	out, err := callTool(t, f.api(""), "search_assets", map[string]any{"query": "payments"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(f.lastQuery, "payments") {
		t.Errorf("the search term never reached the engine: %s", f.lastQuery)
	}
	if !strings.Contains(out, "payments") {
		t.Errorf("output lost the result: %s", out)
	}
}

// get_score_trust is how a model learns whether to present a score as a probability at
// all, so it has to reach the calibration report rather than guessing.
func TestScoreTrustReadsTheCalibrationReport(t *testing.T) {
	f := newFakeEngine(t, `{"calibration":{"hasData":true,"verdict":"underconfident","samples":14,"brier":0.123,"ece":0.255}}`)
	out, err := callTool(t, f.api(""), "get_score_trust", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(f.lastQuery, "calibration") {
		t.Errorf("get_score_trust did not ask for the calibration: %s", f.lastQuery)
	}
	if !strings.Contains(out, "underconfident") {
		t.Errorf("the verdict did not reach the model: %s", out)
	}
}

// ── transport failures ──────────────────────────────────────────────────────

// A tool that cannot reach the engine must say so in a way a model can relay to a
// human, naming the address it tried - "unknown error" sends someone hunting.
func TestUnreachableEngineIsExplained(t *testing.T) {
	api := NewAPI("http://127.0.0.1:1", "")
	_, err := callTool(t, api, "list_fixes", nil)
	if err == nil {
		t.Fatal("an unreachable engine returned no error")
	}
	if !strings.Contains(err.Error(), "unreachable") || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error does not say what was unreachable: %v", err)
	}
}

func TestNonOKStatusIsReported(t *testing.T) {
	f := newFakeEngine(t, `{}`)
	f.status = http.StatusUnauthorized
	_, err := callTool(t, f.api(""), "list_fixes", nil)
	if err == nil {
		t.Fatal("a 401 produced no error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error does not carry the status: %v", err)
	}
}

// A GraphQL-level error arrives with HTTP 200 and an "errors" array; it must not be
// mistaken for a successful empty answer.
func TestGraphQLErrorsAreNotMistakenForSuccess(t *testing.T) {
	f := newFakeEngine(t, `{}`)
	f.errors = `[{"message":"Cannot query field \"nope\""}]`
	_, err := callTool(t, f.api(""), "list_fixes", nil)
	if err == nil {
		t.Fatal("a GraphQL error array was treated as success")
	}
}

// The bearer token is what makes the MCP server usable against a secured engine.
func TestTokenIsSentAsABearerHeader(t *testing.T) {
	f := newFakeEngine(t, `{"remediationPlan":[]}`)
	if _, err := callTool(t, f.api("s3cret"), "list_fixes", nil); err != nil {
		t.Fatalf("call: %v", err)
	}
	if f.lastAuth != "Bearer s3cret" {
		t.Errorf("Authorization header = %q", f.lastAuth)
	}
}

func TestNoTokenSendsNoAuthorizationHeader(t *testing.T) {
	f := newFakeEngine(t, `{"remediationPlan":[]}`)
	if _, err := callTool(t, f.api(""), "list_fixes", nil); err != nil {
		t.Fatalf("call: %v", err)
	}
	if f.lastAuth != "" {
		t.Errorf("an empty token still sent %q", f.lastAuth)
	}
}
