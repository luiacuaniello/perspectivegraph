package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/luiacuaniello/perspectivegraph/internal/mcp"
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
	h, err := a.Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	// Record what reached the engine and what it said back. A tool's error alone is not
	// enough to debug from: search_assets rewrites engine errors into "search is not
	// enabled", and a query-guard rejection surfaces as a bare HTTP status.
	var (
		mu               sync.Mutex
		sent, engineSaid string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		mu.Lock()
		sent, engineSaid = string(body), truncate(rec.Body.String(), 600)
		mu.Unlock()
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	t.Cleanup(srv.Close)

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

	tools := mcp.Tools(mcp.NewAPI(srv.URL, ""))
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
				mu.Lock()
				sent, engineSaid = "", ""
				mu.Unlock()

				out, err := tool.Call(context.Background(), args)

				mu.Lock()
				q, said := sent, engineSaid
				mu.Unlock()
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
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
