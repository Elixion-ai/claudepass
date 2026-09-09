// Package mcp implements the ClaudePass MCP server: a minimal, hand-written
// JSON-RPC 2.0 server that speaks the Model Context Protocol over stdio, so
// a tool-first Agent without a shell can still go through the Broker. Every
// tool handler calls the same internal/run, internal/vault, and
// internal/broker functions the CLI uses, so behaviour (Redaction, Command
// Policy, Bindings) is identical regardless of surface.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"sync"
)

// protocolVersion is offered only when a client's initialize request omits
// one. A well-behaved client always sends its own; this server accepts
// whatever revision the client asks for and echoes it back, since a minimal
// server's behaviour does not vary by revision. This constant is therefore
// only ever a fallback label, not a claim about "the" current revision.
const protocolVersion = "2025-06-18"

// serverName identifies this server in the initialize response.
const serverName = "claudepass"

// request is one JSON-RPC 2.0 request or notification (no ID).
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

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

// server holds the state one Serve call needs.
type server struct {
	out     io.Writer
	mu      sync.Mutex
	version string
}

// Serve reads JSON-RPC 2.0 messages, one per line, from stdin and writes
// responses, one per line, to stdout, until stdin is closed. Requests are
// handled synchronously in the order received, so a response always
// follows the request that produced it before the next line is read — the
// only ordering an MCP stdio client needs. version identifies this build in
// the initialize response; it is passed in (rather than imported from
// internal/cli) so this package stays independent of the CLI.
func Serve(stdin io.Reader, stdout, _ io.Writer, version string) error {
	s := &server{out: stdout, version: version}
	r := bufio.NewReaderSize(stdin, 1<<20)
	for {
		line, rerr := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			s.handleLine(line)
		}
		if rerr != nil {
			if rerr == io.EOF {
				return nil
			}
			return rerr
		}
	}
}

func (s *server) handleLine(line []byte) {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		s.writeMsg(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	if req.Method == "" {
		s.writeError(req.ID, -32600, "invalid request: missing method")
		return
	}
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "notifications/initialized", "notifications/cancelled":
		// Notifications from the client; no response is sent for any method
		// when ID is absent (see writeResult/writeError), so these two
		// names are handled the same as any other notification. Listed
		// explicitly so they never fall into the unknown-method branch and
		// draw a spurious method-not-found error for a stray ID.
	case "ping":
		s.writeResult(req.ID, map[string]any{})
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(req)
	default:
		s.writeError(req.ID, -32601, "method not found: "+req.Method)
	}
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
}

func (s *server) handleInitialize(req request) {
	var p initializeParams
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &p)
	}
	version := p.ProtocolVersion
	if version == "" {
		version = protocolVersion
	}
	s.writeResult(req.ID, map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    serverName,
			"version": s.version,
		},
	})
}

// writeResult and writeError both silently drop responses to notifications
// (ID absent): JSON-RPC 2.0 forbids replying to a request with no ID, and
// this is the one place that rule needs to be enforced.
func (s *server) writeResult(id json.RawMessage, result any) {
	if len(id) == 0 {
		return
	}
	s.writeMsg(response{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *server) writeError(id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		return
	}
	s.writeMsg(response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

func (s *server) writeMsg(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.out.Write(b)
}
