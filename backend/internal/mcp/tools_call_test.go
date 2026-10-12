package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// The engine has no route-by-id query, so the tool reads the ranking until it finds the
// id. It used to read the first 500 routes and stop: route 501 of a large estate was
// "not currently open" while list_attack_paths was showing it.
func TestExplainAttackPathLooksPastTheFirstPage(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		asked = append(asked, body.Query)
		if strings.Contains(body.Query, "offset:") {
			_, _ = w.Write([]byte(`{"data":{"attackPaths":[{"id":"the-one-wanted","score":0.4}]}}`))
			return
		}
		rows := make([]string, explainPage) // a full first page of other routes
		for i := range rows {
			rows[i] = fmt.Sprintf(`{"id":"other-%d"}`, i)
		}
		_, _ = w.Write([]byte(`{"data":{"attackPaths":[` + strings.Join(rows, ",") + `]}}`))
	}))
	t.Cleanup(srv.Close)

	out, err := callTool(t, NewAPI(srv.URL, ""), "explain_attack_path", map[string]any{"path_id": "the-one-wanted"})
	if err != nil {
		t.Fatalf("a route on the second page was not found: %v", err)
	}
	if !strings.Contains(out, `"id":"the-one-wanted"`) {
		t.Errorf("the wrong route came back: %s", out)
	}
	if len(asked) != 2 || !strings.Contains(asked[1], fmt.Sprintf("offset: %d", explainPage)) {
		t.Errorf("want the second page asked for after a full first one, got %d queries: %v", len(asked), asked)
	}
	// The first page carries no offset: an engine older than paging rejects the argument,
	// and nearly every call ends on that page.
	if strings.Contains(asked[0], "offset") {
		t.Errorf("the first page was asked for with an offset an old engine would reject: %s", asked[0])
	}
}

// ── list_attack_paths ───────────────────────────────────────────────────────

const threePaths = `{"attackPaths":[{"id":"p1"},{"id":"p2"},{"id":"p3"}]}`

// A limit with no way past it is a wall: the model sees the top of the ranking and cannot
// tell whether that is all of it. The tool asks the engine for one route more than the
// model asked for, and says whether there was one.
func TestListAttackPathsSaysWhetherThereIsAnotherPage(t *testing.T) {
	f := newFakeEngine(t, threePaths)
	out, err := callTool(t, f.api(""), "list_attack_paths", map[string]any{"limit": float64(2)})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	var page struct {
		AttackPaths []map[string]any `json:"attackPaths"`
		Offset      int              `json:"offset"`
		NextOffset  *int             `json:"nextOffset"`
	}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("output is not the page object: %v\n%s", err, out)
	}
	if len(page.AttackPaths) != 2 || page.AttackPaths[1]["id"] != "p2" {
		t.Errorf("want the two routes asked for, the look-ahead one dropped, got %v", page.AttackPaths)
	}
	if page.NextOffset == nil || *page.NextOffset != 2 {
		t.Errorf("a third route exists, so nextOffset must be 2, got %v in %s", page.NextOffset, out)
	}
	if !strings.Contains(f.lastQuery, "limit: 3") || strings.Contains(f.lastQuery, "offset") {
		t.Errorf("the first page should ask for limit+1 and send no offset: %s", f.lastQuery)
	}

	// The last page: fewer routes than limit+1 came back, so there is nothing after it.
	out, err = callTool(t, f.api(""), "list_attack_paths", map[string]any{"limit": float64(5), "offset": float64(2), "app": "payments-api"})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(out, `"nextOffset":null`) || !strings.Contains(out, `"offset":2`) {
		t.Errorf("the last page must say so with a null nextOffset: %s", out)
	}
	for _, want := range []string{"limit: 6", "offset: 2", `app: "payments-api"`} {
		if !strings.Contains(f.lastQuery, want) {
			t.Errorf("the query lost %q: %s", want, f.lastQuery)
		}
	}
}

// No routes is an answer, and it reads as an empty list. The engine sends null for an
// empty ranking, which a model reads as "the tool returned nothing".
func TestListAttackPathsReturnsNoRoutesAsAnEmptyList(t *testing.T) {
	f := newFakeEngine(t, `{"attackPaths":null}`)
	out, err := callTool(t, f.api(""), "list_attack_paths", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(out, `"attackPaths":[]`) {
		t.Errorf("no routes should read as an empty list, got %s", out)
	}
}

// Glama and the registry run the newest tool against whatever engine an operator has. One
// that predates paging rejects the argument, and the raw rejection reads as a bug in the
// tool rather than as something the model can route around.
func TestListAttackPathsExplainsAnEngineTooOldToPage(t *testing.T) {
	f := newFakeEngine(t, `null`)
	f.errors = `[{"message":"Unknown argument \"offset\" on field \"attackPaths\" of type \"Query\"."}]`
	_, err := callTool(t, f.api(""), "list_attack_paths", map[string]any{"offset": float64(20)})
	if err == nil {
		t.Fatal("an engine that cannot page returned no error")
	}
	for _, want := range []string{"too old", "app", "routes_to_target"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q, so the model has no way forward: %v", want, err)
		}
	}
}

// ── the remaining tools ─────────────────────────────────────────────────────

// The engine indents its replies for people. A tool that hands them on as they are makes
// the model read the indentation, and pay for it, on every call.
func TestAToolHandsOnTheAnswerWithoutItsIndentation(t *testing.T) {
	f := newFakeEngine(t, "{\n  \"remediationPlan\": [\n    {\n      \"title\": \"Scope down the role\"\n    }\n  ]\n}")
	out, err := callTool(t, f.api(""), "list_fixes", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if want := `{"remediationPlan":[{"title":"Scope down the role"}]}`; out != want {
		t.Errorf("got  %q\nwant %q", out, want)
	}
}

// The engine computes a triage priority for the ranked routes only. Asked for here, it came
// back 0 on every route and reached the model as a fact. The hops are what this tool has to
// return: an alternate route is in no ranking, so explain_attack_path cannot supply them.
func TestRoutesToTargetAsksForTheHopsAndNoPriority(t *testing.T) {
	f := newFakeEngine(t, `{"kShortestPaths":[]}`)
	if _, err := callTool(t, f.api(""), "routes_to_target", map[string]any{"target": "payments-admin"}); err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(f.lastQuery, "steps") || !strings.Contains(f.lastQuery, "weightBasis") {
		t.Errorf("the query does not ask for each route's hops: %s", f.lastQuery)
	}
	if strings.Contains(f.lastQuery, "priority") {
		t.Errorf("the query asks for a priority the engine does not compute for these routes: %s", f.lastQuery)
	}
}

// get_posture is where an agent starts, so it is where the names the other tools take
// have to be: `app` was a parameter with no way to learn a valid value.
func TestPostureListsTheApplicationNames(t *testing.T) {
	f := newFakeEngine(t, `{"posture":{"activePaths":3},"applications":["payments-api"]}`)
	out, err := callTool(t, f.api(""), "get_posture", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(f.lastQuery, "applications") || !strings.Contains(out, "payments-api") {
		t.Errorf("the application names did not reach the model\nasked: %s\ngot:   %s", f.lastQuery, out)
	}
}

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
	// The type was read from the arguments and never sent: the cut above removed every
	// relationship from edge-alb to payments, not the one it named.
	if !strings.Contains(f.lastQuery, `type: "EXPOSES"`) {
		t.Errorf("the relationship type was dropped, so the cut is broader than asked: %s", f.lastQuery)
	}

	// Without a type the cut is every relationship between the two nodes, and no empty
	// type may be sent in its place: the engine would look for a relationship named "".
	if _, err := callTool(t, f.api(""), "simulate_fix", map[string]any{
		"cuts": []any{map[string]any{"from": "edge-alb", "to": "payments"}},
	}); err != nil {
		t.Fatalf("call: %v", err)
	}
	if strings.Contains(f.lastQuery, "type:") {
		t.Errorf("a cut with no type sent one anyway: %s", f.lastQuery)
	}
}

func TestSearchAssetsPassesTheQueryThrough(t *testing.T) {
	f := newFakeEngine(t, `{"searchEnabled":true,"search":[{"id":"n1","name":"payments","label":"Container"}]}`)
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

// With OpenSearch off the engine does not fail: its indexer answers "no hits". An agent
// handed that reads "no asset by that name exists" - a false negative about the estate -
// so the tool must ask whether search is on at all, and say so when it is not.
func TestSearchAssetsSaysSearchIsOffRatherThanReportingNoMatches(t *testing.T) {
	f := newFakeEngine(t, `{"searchEnabled":false,"search":null}`)
	out, err := callTool(t, f.api(""), "search_assets", map[string]any{"query": "payments"})
	if !errors.Is(err, ErrSearchDisabled) {
		t.Fatalf("search off: got output %q and error %v, want ErrSearchDisabled", out, err)
	}
	if !strings.Contains(f.lastQuery, "searchEnabled") {
		t.Errorf("the tool never asked whether search is enabled: %s", f.lastQuery)
	}
}

// The mirror image: search IS on and the engine failed. Every OpenSearch error carries the
// `_search` URL, and the old check - any error mentioning "search" - turned an outage into
// "search is not enabled on this deployment", which is false and sends the operator
// looking for a configuration problem that does not exist.
func TestSearchAssetsReportsARealFailureAsTheFailure(t *testing.T) {
	f := newFakeEngine(t, `null`)
	f.errors = `[{"message":"POST http://opensearch:9200/pg-default/_search?ignore_unavailable=true: dial tcp 10.0.0.7:9200: connect: connection refused","path":["search"]}]`
	_, err := callTool(t, f.api(""), "search_assets", map[string]any{"query": "payments"})
	if err == nil {
		t.Fatal("an engine error was swallowed")
	}
	if errors.Is(err, ErrSearchDisabled) || strings.Contains(err.Error(), "not enabled") {
		t.Errorf("an OpenSearch outage was reported as search being disabled: %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("the real cause did not reach the agent: %v", err)
	}
}

// Search on, nothing found: an empty result is the answer, not an error.
func TestSearchAssetsReturnsNoMatchesAsAnEmptyResult(t *testing.T) {
	f := newFakeEngine(t, `{"searchEnabled":true,"search":[]}`)
	out, err := callTool(t, f.api(""), "search_assets", map[string]any{"query": "nothing-like-this"})
	if err != nil {
		t.Fatalf("no matches returned an error: %v", err)
	}
	if !strings.Contains(out, `"search":[]`) {
		t.Errorf("no matches should read as an empty list, got %s", out)
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
	if !strings.Contains(err.Error(), "retry once") {
		t.Errorf("error does not say whether trying again can help: %v", err)
	}
}

// "HTTP 401" is a number; what a model needs is its next move. A refused token will be
// refused again and only the user can change it; a rate limit and a failing engine pass.
// Told nothing, an agent retries the first in a loop and gives up on the others.
func TestAFailedCallSaysWhatToDoNext(t *testing.T) {
	for _, c := range []struct {
		status int
		want   []string
		never  string
	}{
		{http.StatusUnauthorized, []string{"401", "will not help", "API_TOKEN"}, "retry once"},
		{http.StatusForbidden, []string{"403", "will not help"}, "retry once"},
		{http.StatusTooManyRequests, []string{"429", "wait", "repeat"}, "will not help"},
		{http.StatusServiceUnavailable, []string{"503", "retry once"}, "will not help"},
		{http.StatusBadRequest, []string{"400", "will fail again"}, "retry once"},
	} {
		f := newFakeEngine(t, `{}`)
		f.status = c.status
		_, err := callTool(t, f.api(""), "list_fixes", nil)
		if err == nil {
			t.Errorf("HTTP %d produced no error", c.status)
			continue
		}
		for _, want := range c.want {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("HTTP %d: the error does not say %q: %v", c.status, want, err)
			}
		}
		if strings.Contains(err.Error(), c.never) {
			t.Errorf("HTTP %d: the error gives the wrong advice (%q): %v", c.status, c.never, err)
		}
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
