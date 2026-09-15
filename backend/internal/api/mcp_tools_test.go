package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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

	// Arguments are spliced into the query text, so each optional argument is its own
	// query shape and gets its own entry. Numbers are float64 because that is how they
	// arrive from a model's JSON. Names come from seededAPI's estate.
	samples := map[string][]map[string]any{
		"get_posture":         {{}},
		"list_attack_paths":   {{}, {"limit": float64(5), "app": "payments-api"}},
		"explain_attack_path": {{"path_id": pathID}},
		"routes_to_target":    {{"target": "payments-admin"}, {"target": "payments-admin", "k": float64(3), "from": "edge-alb"}},
		"list_fixes":          {{}, {"app": "payments-api"}},
		"simulate_fix":        {{"cuts": []any{map[string]any{"from": "lb", "to": "svc"}}}},
		"search_assets":       {{"query": "payments", "size": float64(5)}},
		"get_score_trust":     {{}},
	}

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
