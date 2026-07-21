// Package mcp exposes the attack-path engine as tools an AI agent can call,
// over the Model Context Protocol (JSON-RPC 2.0 on stdio).
//
// Why this exists: a language model is bad at exactly what this engine is good at.
// It cannot enumerate fourteen thousand edges reliably, it does not run Dijkstra,
// and asked for "the attack paths in my account" it will produce plausible routes
// that do not exist. The engine is deterministic, exhaustive and reproducible. So
// the useful arrangement is not an LLM that decorates the engine's output - which
// is what the /ai endpoints do - but an agent that CALLS the engine and reasons
// over answers it could not have invented.
//
// Two deliberate constraints:
//
//   - Read-only. No tool here suppresses a path, opens a pull request or records a
//     verdict. Those change state a human is accountable for, and an agent that can
//     silently mark risks as accepted is a liability, not a feature.
//   - Honest by construction. Every tool that returns a score also returns how much
//     that score can be trusted (see get_score_trust), and the descriptions say
//     plainly that the probabilities are expert estimates, not field-calibrated
//     measurements. An agent that reads a tool description is the one consumer that
//     will actually propagate that caveat.
//
// The protocol is hand-rolled over encoding/json for the same reason the Anthropic
// client is: it is a few hundred lines of JSON-RPC, and the engine's dependency
// list is a feature.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// defaultProtocolVersion is what we advertise when a client does not name one.
// When it does, we echo it back: MCP clients negotiate by sending the version they
// speak, and a server that insists on its own build date fails handshakes it could
// have served.
const defaultProtocolVersion = "2024-11-05"

// request is an incoming JSON-RPC 2.0 message. A message with no ID is a
// notification: it expects no reply, and answering one is a protocol error.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (r request) isNotification() bool { return len(r.ID) == 0 }

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC 2.0 reserved codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInternalError  = -32603
)

// Tool is one callable capability. InputSchema is JSON Schema: it is the contract
// the agent plans against, so it carries the real constraints (bounds, enums)
// rather than accepting anything and failing at call time.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`

	// Call runs the tool. The returned string is what the model reads, so it should
	// be compact and self-describing - JSON the model can quote back, not prose.
	Call func(ctx context.Context, args map[string]any) (string, error) `json:"-"`
}

// Server is an MCP server over a set of tools.
type Server struct {
	name    string
	version string
	tools   []Tool
	byName  map[string]Tool

	mu sync.Mutex // serializes writes: responses must not interleave on the wire
	w  *bufio.Writer
}

// NewServer builds a server exposing tools, in the order given (tools/list order is
// what an agent sees first, so put orientation before detail).
func NewServer(name, version string, tools []Tool) *Server {
	byName := make(map[string]Tool, len(tools))
	for _, t := range tools {
		byName[t.Name] = t
	}
	return &Server{name: name, version: version, tools: tools, byName: byName}
}

// Serve runs the stdio transport: one JSON message per line, in and out, until the
// reader closes or the context is cancelled. Errors inside a tool are reported to
// the model as tool results (isError), not as transport failures - a model can
// recover from "that path id does not exist" but not from a dead connection.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	s.w = bufio.NewWriter(w)
	sc := bufio.NewScanner(r)
	// Tool payloads (a hundred scored paths) exceed bufio's default 64KiB line cap.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.reply(response{JSONRPC: "2.0", Error: &rpcError{codeParseError, "invalid JSON"}})
			continue
		}
		s.dispatch(ctx, req)
	}
	return sc.Err()
}

func (s *Server) dispatch(ctx context.Context, req request) {
	switch req.Method {
	case "initialize":
		s.reply(response{JSONRPC: "2.0", ID: req.ID, Result: s.initializeResult(req.Params)})

	case "notifications/initialized", "notifications/cancelled":
		// Notifications carry no ID and must not be answered.

	case "ping":
		s.reply(response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}})

	case "tools/list":
		s.reply(response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": s.tools}})

	case "tools/call":
		s.reply(response{JSONRPC: "2.0", ID: req.ID, Result: s.callTool(ctx, req.Params)})

	default:
		if req.isNotification() {
			return
		}
		s.reply(response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{codeMethodNotFound, "unknown method " + req.Method}})
	}
}

// initializeResult echoes the client's protocol version when it names one, so the
// handshake succeeds across MCP revisions instead of failing on a date string.
func (s *Server) initializeResult(params json.RawMessage) map[string]any {
	version := defaultProtocolVersion
	if len(params) > 0 {
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(params, &p) == nil && p.ProtocolVersion != "" {
			version = p.ProtocolVersion
		}
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": s.name, "version": s.version},
	}
}

// callTool runs one tool and shapes the MCP result. A tool failure is returned as
// an errored tool RESULT rather than a JSON-RPC error, because the model is the
// one that can act on it: it sees the message and can retry with better arguments.
func (s *Server) callTool(ctx context.Context, params json.RawMessage) map[string]any {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return toolResult("malformed tools/call params", true)
	}
	tool, ok := s.byName[p.Name]
	if !ok {
		return toolResult(fmt.Sprintf("no such tool %q", p.Name), true)
	}
	out, err := tool.Call(ctx, p.Arguments)
	if err != nil {
		return toolResult(err.Error(), true)
	}
	return toolResult(out, false)
}

func toolResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func (s *Server) reply(resp response) {
	if resp.ID == nil && resp.Error == nil {
		return // nothing to say about a notification
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(resp)
	if err != nil {
		b, _ = json.Marshal(response{JSONRPC: "2.0", ID: resp.ID, Error: &rpcError{codeInternalError, "response encode failed"}})
	}
	_, _ = s.w.Write(b)
	_ = s.w.WriteByte('\n')
	_ = s.w.Flush()
}
