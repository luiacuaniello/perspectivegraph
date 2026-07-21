package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A conversation with the server: write the client's lines, read back every reply.
func converse(t *testing.T, srv *Server, lines ...string) []map[string]any {
	t.Helper()
	var out strings.Builder
	if err := srv.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var got []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("server emitted non-JSON line %q: %v", l, err)
		}
		got = append(got, m)
	}
	return got
}

func testServer(tools ...Tool) *Server { return NewServer("perspectivegraph", "test", tools) }

func echoTool() Tool {
	return Tool{
		Name: "echo", Description: "echoes", InputSchema: obj(map[string]any{}),
		Call: func(_ context.Context, args map[string]any) (string, error) {
			if args["fail"] == true {
				return "", fmt.Errorf("deliberate failure")
			}
			return fmt.Sprintf("got %v", args["value"]), nil
		},
	}
}

func TestHandshakeEchoesClientProtocolVersion(t *testing.T) {
	// MCP clients negotiate by naming the version they speak. A server that insists
	// on its own build date fails handshakes it could have served.
	got := converse(t, testServer(echoTool()),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	res := got[0]["result"].(map[string]any)
	if res["protocolVersion"] != "2025-06-18" {
		t.Errorf("protocolVersion = %v, want the client's 2025-06-18", res["protocolVersion"])
	}
	if _, ok := res["capabilities"].(map[string]any)["tools"]; !ok {
		t.Error("server must advertise the tools capability")
	}
}

func TestHandshakeFallsBackWhenClientNamesNoVersion(t *testing.T) {
	got := converse(t, testServer(echoTool()), `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if v := got[0]["result"].(map[string]any)["protocolVersion"]; v != defaultProtocolVersion {
		t.Errorf("protocolVersion = %v, want the default %s", v, defaultProtocolVersion)
	}
}

func TestNotificationsAreNeverAnswered(t *testing.T) {
	// Replying to a notification is a protocol violation that desynchronizes strict
	// clients, so the initialized/cancelled notices must produce no output at all.
	got := converse(t, testServer(echoTool()),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled"}`)
	if len(got) != 0 {
		t.Errorf("notifications produced %d replies, want 0: %v", len(got), got)
	}
}

func TestToolsListCarriesSchemas(t *testing.T) {
	got := converse(t, testServer(echoTool()), `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := got[0]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "echo" || tool["description"] == "" {
		t.Errorf("tool advertised badly: %v", tool)
	}
	// The schema is the contract the agent plans against; it must be present.
	if _, ok := tool["inputSchema"].(map[string]any); !ok {
		t.Error("tool must advertise an inputSchema")
	}
}

func TestToolCallReturnsContent(t *testing.T) {
	got := converse(t, testServer(echoTool()),
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"value":42}}}`)
	res := got[0]["result"].(map[string]any)
	if res["isError"] != false {
		t.Errorf("isError = %v, want false", res["isError"])
	}
	text := res["content"].([]any)[0].(map[string]any)["text"]
	if text != "got 42" {
		t.Errorf("text = %v, want 'got 42'", text)
	}
}

func TestToolFailureIsAResultNotATransportError(t *testing.T) {
	// A model can recover from "that id does not exist" if it arrives as a tool
	// result it can read. A JSON-RPC error aborts the call instead.
	for _, c := range []struct{ name, line string }{
		{"tool returned an error", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"fail":true}}}`},
		{"unknown tool", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope","arguments":{}}}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := converse(t, testServer(echoTool()), c.line)
			if _, isRPCError := got[0]["error"]; isRPCError {
				t.Fatal("tool trouble must not surface as a JSON-RPC error")
			}
			res := got[0]["result"].(map[string]any)
			if res["isError"] != true {
				t.Errorf("isError = %v, want true", res["isError"])
			}
		})
	}
}

func TestUnknownMethodAndBadJSON(t *testing.T) {
	got := converse(t, testServer(echoTool()),
		`{"jsonrpc":"2.0","id":6,"method":"does/not/exist"}`,
		`{not json`)
	if got[0]["error"].(map[string]any)["code"] != float64(codeMethodNotFound) {
		t.Errorf("unknown method should yield %d, got %v", codeMethodNotFound, got[0]["error"])
	}
	if got[1]["error"].(map[string]any)["code"] != float64(codeParseError) {
		t.Errorf("malformed JSON should yield %d, got %v", codeParseError, got[1]["error"])
	}
}

// TestToolsSpeakToTheModelAboutTrust pins the property that makes this server worth
// shipping: an agent reading the descriptions is told, before it ever quotes a
// number, that the scores are estimates and how to check them.
func TestToolsSpeakToTheModelAboutTrust(t *testing.T) {
	tools := Tools(NewAPI("http://example.invalid", ""))
	byName := map[string]Tool{}
	for _, tl := range tools {
		byName[tl.Name] = tl
	}
	for _, want := range []string{"get_posture", "list_attack_paths", "explain_attack_path", "simulate_fix", "get_score_trust"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("missing tool %s", want)
		}
	}
	paths := byName["list_attack_paths"].Description
	if !strings.Contains(paths, "get_score_trust") || !strings.Contains(paths, "estimates") {
		t.Error("list_attack_paths must warn the model the scores are estimates and point at get_score_trust")
	}
	// No tool may mutate state: an agent that can silently accept a risk is a
	// liability, so the read-only boundary is asserted, not just documented.
	for _, tl := range tools {
		for _, verb := range []string{"suppress", "create_ticket", "open_pr", "record_verdict", "delete"} {
			if strings.Contains(tl.Name, verb) {
				t.Errorf("tool %q mutates state; the MCP surface is read-only by design", tl.Name)
			}
		}
	}
}

// TestToolsQueryTheEngine drives a tool against a stub API, proving the GraphQL
// round-trip and that engine-side errors reach the model as readable text.
func TestToolsQueryTheEngine(t *testing.T) {
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		lastQuery = body.Query
		if strings.Contains(body.Query, "kShortestPaths") {
			_, _ = w.Write([]byte(`{"errors":[{"message":"unknown target"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"posture":{"activePaths":14},"riskSimulation":{"anyCompromiseProbability":1}}}`))
	}))
	defer srv.Close()
	api := NewAPI(srv.URL, "tok")

	out, err := posture(api).Call(context.Background(), nil)
	if err != nil {
		t.Fatalf("get_posture: %v", err)
	}
	if !strings.Contains(out, "activePaths") {
		t.Errorf("get_posture returned %q", out)
	}

	// A limit above the schema's ceiling is clamped, not forwarded.
	if _, err := listPaths(api).Call(context.Background(), map[string]any{"limit": float64(9999)}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastQuery, "limit: 100") {
		t.Errorf("limit should clamp to 100, query was: %s", lastQuery)
	}

	// An engine-side rejection becomes a message the model can act on.
	if _, err := routesToTarget(api).Call(context.Background(), map[string]any{"target": "ghost"}); err == nil ||
		!strings.Contains(err.Error(), "unknown target") {
		t.Errorf("engine errors should reach the model verbatim, got %v", err)
	}
}

func TestJSONStringEscapesModelInput(t *testing.T) {
	// Model-supplied strings reach the GraphQL query text, so they are encoded.
	if got := jsonString(`a" b\`); got != `"a\" b\\"` {
		t.Errorf("jsonString = %s", got)
	}
}
