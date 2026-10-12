package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/mcp"
	"github.com/luiacuaniello/perspectivegraph/internal/search"
	"github.com/luiacuaniello/perspectivegraph/pkg/ontology"
)

// The MCP tools are unit-tested against a fake engine, which pins what a tool ASKS but
// not whether the real engine would ANSWER: a misspelled field passes there, and fails
// only when an agent calls the tool in front of a user. So every tool is run here through
// its own Call, over HTTP, against the real handler - the schema, the query guard and the
// argument encoding the agent actually gets, rather than a copy of the query text that
// could drift from what the tool sends.
//
// This lives in package api, not mcp, because this is where a seeded engine can be built.
// It adds no cycle: internal/mcp imports nothing from this module.
func TestEveryMCPToolIsAcceptedByTheRealEngine(t *testing.T) {
	a := seededAPI(t)
	// Search ON, so search_assets is exercised on the path that returns hits. Set before
	// the handler serves anything. With search off the tool answers differently, and
	// that answer has its own test below.
	a.search = enabledSearch{hits: []search.Hit{{ID: "n1", Name: "payments-api", Label: "Container", Score: 1}}}
	eng := recordingEngine(t, a)

	paths, _ := query(t, a, `{ attackPaths(limit: 1) { id } }`)["attackPaths"].([]any)
	if len(paths) == 0 {
		t.Fatal("the seeded estate has no attack path to explain")
	}
	pathID, _ := paths[0].(map[string]any)["id"].(string)

	samples := mcpSamples(pathID)

	tools := mcp.Tools(mcp.NewAPI(eng.url, ""))
	if len(tools) == 0 {
		t.Fatal("mcp.Tools returned no tools to check")
	}
	registered := map[string]bool{}
	for _, tool := range tools {
		registered[tool.Name] = true
		argSets, ok := samples[tool.Name]
		if !ok {
			t.Errorf("%s has no sample arguments, so nothing checks its query against the real engine - add an entry", tool.Name)
			continue
		}
		t.Run(tool.Name, func(t *testing.T) {
			for _, args := range argSets {
				eng.reset()
				out, err := tool.Call(context.Background(), args)
				q, said := eng.last()
				switch {
				case q == "":
					t.Errorf("args %v: the tool sent no query (%v) - the sample arguments no longer satisfy it", args, err)
				case err != nil:
					t.Errorf("args %v: the real engine rejected the tool's query: %v\nsent:   %s\nengine: %s", args, err, q, said)
				case out == "" || out == "null":
					t.Errorf("args %v: the query was accepted but the tool returned nothing\nsent: %s", args, q)
				}
			}
		})
	}
	for name := range samples {
		if !registered[name] {
			t.Errorf("sample arguments for %q, which is no longer a tool - rename or remove the entry", name)
		}
	}

	// The hit has to come back as a hit: this is the path that returned `{"search":null}`
	// - read by an agent as "nothing by that name" - on every deployment without OpenSearch.
	out, err := toolNamed(t, tools, "search_assets").Call(context.Background(), map[string]any{"query": "payments"})
	if err != nil || !strings.Contains(out, "payments-api") {
		t.Errorf("search on: output %q, error %v - want the indexed hit", out, err)
	}
}

// mcpSamples is one set of arguments per query shape of each tool. Arguments are spliced
// into the query text, so each optional argument is its own shape and gets its own entry.
// Numbers are float64 because that is how they arrive from a model's JSON. Names come from
// seededAPI's estate.
func mcpSamples(pathID string) map[string][]map[string]any {
	return map[string][]map[string]any{
		"get_posture": {{}},
		"list_attack_paths": {{}, {"limit": float64(5), "app": "payments-api"},
			{"limit": float64(1), "offset": float64(1)}},
		"explain_attack_path": {{"path_id": pathID}},
		"routes_to_target":    {{"target": "payments-admin"}, {"target": "payments-admin", "k": float64(3), "from": "edge-alb"}},
		"list_fixes":          {{}, {"app": "payments-api"}},
		// The last cut matches no relationship, so the route stays open and `after` has a
		// row to hold to the schema.
		"simulate_fix": {{"cuts": []any{map[string]any{"from": "lb", "to": "svc"}}},
			{"cuts": []any{map[string]any{"from": "lb", "to": "svc", "type": "EXPOSES"}}},
			{"cuts": []any{map[string]any{"from": "billing", "to": "svc"}}}},
		"search_assets":   {{"query": "payments", "size": float64(5)}},
		"get_score_trust": {{}},
	}
}

// An output schema is a second copy of what a tool returns, kept by hand beside the query
// that decides it. Add a field to the query and forget the schema, and a client that
// validates results rejects a call that worked; drop one and the schema promises a field
// that never comes. So every tool is run against the real engine and its result is held to
// its own schema, both ways: nothing returned that is not declared, nothing declared that
// is not returned.
func TestEveryMCPToolReturnsWhatItDeclares(t *testing.T) {
	a := seededAPI(t)
	a.search = enabledSearch{hits: []search.Hit{{ID: "n1", Name: "payments-api", Label: "Container", Score: 1}}}
	eng := recordingEngine(t, a)

	paths, _ := query(t, a, `{ attackPaths(limit: 1) { id } }`)["attackPaths"].([]any)
	if len(paths) == 0 {
		t.Fatal("the seeded estate has no attack path to explain")
	}
	pathID, _ := paths[0].(map[string]any)["id"].(string)
	samples := mcpSamples(pathID)

	for _, tool := range mcp.Tools(mcp.NewAPI(eng.url, "")) {
		t.Run(tool.Name, func(t *testing.T) {
			raw, err := json.Marshal(tool.OutputSchema)
			if err != nil || tool.OutputSchema == nil {
				t.Fatalf("no usable output schema (%v)", err)
			}
			var schema map[string]any
			_ = json.Unmarshal(raw, &schema)

			seen := map[string]bool{}
			for _, args := range samples[tool.Name] {
				out, err := tool.Call(context.Background(), args)
				if err != nil {
					t.Fatalf("args %v: %v", args, err)
				}
				var result any
				if err := json.Unmarshal([]byte(out), &result); err != nil {
					t.Fatalf("args %v: the result is not JSON: %v\n%s", args, err, out)
				}
				for _, problem := range conforms("result", schema, result, seen) {
					t.Errorf("args %v: %s", args, problem)
				}
			}
			// A list that came back empty, or an object that came back null, in every
			// sample hides its fields from the check above. Say so rather than pass in
			// silence: the fix is a sample, or seeded data, that fills it.
			for _, where := range declaredObjects("result", schema) {
				if !seen[where] {
					t.Logf("not exercised by any sample: %s", where)
				}
			}
		})
	}
}

// The engine ranks the best route from each entry point to each target. routes_to_target
// also returns the alternates, which are in no ranking - so explain_attack_path, which
// reads the ranking, cannot find them, and said such a route was "not currently open"
// while the other tool was showing it. An alternate therefore comes with its own hops, and
// the refusal says where they are. It also came with a priority of 0 on every route: the
// engine computes none here, and the tool was passing the zero through as a fact.
func TestMCPAlternateRouteCarriesItsOwnHops(t *testing.T) {
	// One entry point, two ways to the role: through `a` (likely) and through `b` (less).
	a := estateAPI(t, 1, func(node func(ontology.Node), exposes func(from, to string, p float64)) {
		node(ontology.Node{ID: "lb", Label: ontology.LabelLoadBalancer, Name: "edge-alb",
			Properties: map[string]any{ontology.PropInternetExposed: true}})
		node(ontology.Node{ID: "a", Label: ontology.LabelContainer, Name: "api"})
		node(ontology.Node{ID: "b", Label: ontology.LabelContainer, Name: "batch"})
		node(ontology.Node{ID: "role", Label: ontology.LabelIAMRole, Name: "payments-admin",
			Properties: map[string]any{ontology.PropCrownJewel: true}})
		exposes("lb", "a", 0.9)
		exposes("a", "role", 0.9)
		exposes("lb", "b", 0.5)
		exposes("b", "role", 0.5)
	})
	tools := mcp.Tools(mcp.NewAPI(recordingEngine(t, a).url, ""))
	ctx := context.Background()

	out, err := toolNamed(t, tools, "routes_to_target").Call(ctx, map[string]any{"target": "payments-admin"})
	if err != nil {
		t.Fatalf("routes_to_target: %v", err)
	}
	var routes struct {
		Routes []struct {
			ID    string
			Steps []struct{ From, To string }
			Extra map[string]any `json:"-"`
		} `json:"kShortestPaths"`
	}
	if err := json.Unmarshal([]byte(out), &routes); err != nil || len(routes.Routes) != 2 {
		t.Fatalf("want the two routes to the role, got %v: %s", err, out)
	}
	if strings.Contains(out, "priority") {
		t.Errorf("a priority the engine does not compute here is being reported: %s", out)
	}
	alternate := routes.Routes[1]
	if len(alternate.Steps) != 2 || alternate.Steps[0].From != "lb" || alternate.Steps[1].To != "role" {
		t.Fatalf("the alternate route must carry its hops, got %+v", alternate.Steps)
	}

	// The hops are what an agent needs the route for: cutting one must be possible
	// without a detour through the tool that cannot find it.
	cut, err := toolNamed(t, tools, "simulate_fix").Call(ctx, map[string]any{
		"cuts": []any{map[string]any{"from": alternate.Steps[0].From, "to": alternate.Steps[0].To}}})
	if err != nil || !strings.Contains(cut, `"removedEdges":1`) {
		t.Errorf("a hop taken from the alternate route did not cut one relationship: %v %s", err, cut)
	}

	if _, err := toolNamed(t, tools, "explain_attack_path").Call(ctx, map[string]any{"path_id": routes.Routes[0].ID}); err != nil {
		t.Errorf("the ranked route must still be explainable: %v", err)
	}
	_, err = toolNamed(t, tools, "explain_attack_path").Call(ctx, map[string]any{"path_id": alternate.ID})
	if err == nil {
		t.Fatal("explain_attack_path now finds alternate routes: say so in routes_to_target's schema, which tells agents it does not")
	}
	if !strings.Contains(err.Error(), "routes_to_target") {
		t.Errorf("the refusal does not say where an alternate route's hops are: %v", err)
	}
}

// conforms holds a value to a JSON Schema in the subset the tools use - type (with null),
// properties, items - and is stricter than a client: an object must carry exactly the
// properties declared. The engine returns every field a query selects, null or not, so a
// declared field that is absent is one the tool no longer asks for.
func conforms(where string, schema map[string]any, v any, seen map[string]bool) []string {
	var problems []string
	got := "null"
	switch x := v.(type) {
	case bool:
		got = "boolean"
	case string:
		got = "string"
	case float64:
		got = "number"
		if x == float64(int64(x)) {
			got = "integer"
		}
	case []any:
		got = "array"
	case map[string]any:
		got = "object"
	}
	allowed := map[string]bool{}
	switch ty := schema["type"].(type) {
	case string:
		allowed[ty] = true
	case []any:
		for _, one := range ty {
			s, _ := one.(string)
			allowed[s] = true
		}
	}
	if !allowed[got] && (got != "integer" || !allowed["number"]) {
		return []string{fmt.Sprintf("%s is %s, and the schema allows %v", where, got, schema["type"])}
	}
	switch x := v.(type) {
	case []any:
		items, _ := schema["items"].(map[string]any)
		for _, el := range x {
			problems = append(problems, conforms(where+"[]", items, el, seen)...)
		}
	case map[string]any:
		seen[where] = true
		props, _ := schema["properties"].(map[string]any)
		for key := range x {
			if _, ok := props[key]; !ok {
				problems = append(problems, fmt.Sprintf("%s.%s is returned and not declared", where, key))
			}
		}
		for key, sub := range props {
			child, ok := x[key]
			if !ok {
				problems = append(problems, fmt.Sprintf("%s.%s is declared and not returned", where, key))
				continue
			}
			subSchema, _ := sub.(map[string]any)
			problems = append(problems, conforms(where+"."+key, subSchema, child, seen)...)
		}
	}
	sort.Strings(problems)
	return problems
}

// declaredObjects lists where a schema declares an object with fields of its own.
func declaredObjects(where string, schema map[string]any) []string {
	var out []string
	if items, ok := schema["items"].(map[string]any); ok {
		out = append(out, declaredObjects(where+"[]", items)...)
	}
	props, _ := schema["properties"].(map[string]any)
	if len(props) > 0 {
		out = append(out, where)
	}
	for key, sub := range props {
		if subSchema, ok := sub.(map[string]any); ok {
			out = append(out, declaredObjects(where+"."+key, subSchema)...)
		}
	}
	sort.Strings(out)
	return out
}

// Without OpenSearch the real engine does not fail - its indexer answers "no hits" - so
// the only thing that tells an agent search is off is the tool asking. Run against the
// real handler, the query must be accepted AND the answer must be ErrSearchDisabled.
func TestMCPSearchSaysSearchIsOffOnTheRealEngine(t *testing.T) {
	a := seededAPI(t) // search.Noop, as on any deployment without OPENSEARCH_URL
	eng := recordingEngine(t, a)
	tool := toolNamed(t, mcp.Tools(mcp.NewAPI(eng.url, "")), "search_assets")

	out, err := tool.Call(context.Background(), map[string]any{"query": "payments"})
	q, said := eng.last()
	if !errors.Is(err, mcp.ErrSearchDisabled) {
		t.Fatalf("search off: output %q, error %v, want ErrSearchDisabled\nsent:   %s\nengine: %s", out, err, q, said)
	}
	if strings.Contains(said, `"errors"`) {
		t.Errorf("the engine rejected the query rather than reporting search off:\nsent:   %s\nengine: %s", q, said)
	}
}

// recordingEngine serves a's real handler and remembers the last request and reply. A
// tool's error alone is not enough to debug from: a query-guard rejection surfaces as a
// bare HTTP status.
type engineRecorder struct {
	url              string
	mu               sync.Mutex
	sent, engineSaid string
}

func recordingEngine(t *testing.T, a *API) *engineRecorder {
	t.Helper()
	h, err := a.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	e := &engineRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		e.mu.Lock()
		e.sent, e.engineSaid = string(body), truncate(rec.Body.String(), 600)
		e.mu.Unlock()
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	t.Cleanup(srv.Close)
	e.url = srv.URL
	return e
}

func (e *engineRecorder) reset() {
	e.mu.Lock()
	e.sent, e.engineSaid = "", ""
	e.mu.Unlock()
}

func (e *engineRecorder) last() (sent, engineSaid string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sent, e.engineSaid
}

func toolNamed(t *testing.T, tools []mcp.Tool, name string) mcp.Tool {
	t.Helper()
	for _, tl := range tools {
		if tl.Name == name {
			return tl
		}
	}
	t.Fatalf("tool %q is not registered", name)
	return mcp.Tool{}
}

// enabledSearch is an indexer that is switched on and returns fixed hits.
type enabledSearch struct{ hits []search.Hit }

func (enabledSearch) Enabled() bool                                        { return true }
func (enabledSearch) Index(context.Context, string, []ontology.Node) error { return nil }
func (s enabledSearch) Search(context.Context, string, string, int) ([]search.Hit, error) {
	return s.hits, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
