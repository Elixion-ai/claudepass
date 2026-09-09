package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Unit tests here cover only the pure JSON-RPC framing/dispatch core: line
// parsing, notification suppression, initialize negotiation, and the
// tools/list shape. Behaviour that touches the Vault or spawns a command
// (list_handles, run_with_secrets, capture) is exercised end-to-end in
// internal/e2e against the built binary, the boundary an Agent uses.

// serveOne runs Serve to completion over the given input lines and returns
// every response line it wrote.
func serveOne(t *testing.T, lines ...string) []map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	var out bytes.Buffer
	if err := Serve(in, &out, &bytes.Buffer{}, "test"); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var got []map[string]any
	sc := bytes.Split(bytes.TrimRight(out.Bytes(), "\n"), []byte("\n"))
	for _, line := range sc {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("response line not valid JSON %q: %v", line, err)
		}
		got = append(got, m)
	}
	return got
}

func TestParseErrorGetsJSONRPCError(t *testing.T) {
	got := serveOne(t, `not json`)
	if len(got) != 1 {
		t.Fatalf("want 1 response, got %d: %v", len(got), got)
	}
	errObj, ok := got[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("want an error response: %v", got[0])
	}
	if code, _ := errObj["code"].(float64); code != -32700 {
		t.Fatalf("want -32700, got %v", errObj["code"])
	}
}

func TestNotificationProducesNoResponse(t *testing.T) {
	got := serveOne(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if len(got) != 0 {
		t.Fatalf("notification should produce no response, got %v", got)
	}
}

func TestUnknownMethodOnARequestIsMethodNotFound(t *testing.T) {
	got := serveOne(t, `{"jsonrpc":"2.0","id":1,"method":"nonsense"}`)
	if len(got) != 1 {
		t.Fatalf("want 1 response, got %v", got)
	}
	errObj, ok := got[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("want an error response: %v", got[0])
	}
	if code, _ := errObj["code"].(float64); code != -32601 {
		t.Fatalf("want -32601, got %v", errObj["code"])
	}
}

func TestInitializeEchoesClientProtocolVersion(t *testing.T) {
	got := serveOne(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01","clientInfo":{"name":"x","version":"0"}}}`)
	if len(got) != 1 {
		t.Fatalf("want 1 response, got %v", got)
	}
	result, ok := got[0]["result"].(map[string]any)
	if !ok {
		t.Fatalf("want a result, got %v", got[0])
	}
	if result["protocolVersion"] != "2099-01-01" {
		t.Fatalf("protocolVersion not echoed: %v", result)
	}
	info, ok := result["serverInfo"].(map[string]any)
	if !ok || info["name"] != "claudepass" || info["version"] != "test" {
		t.Fatalf("serverInfo: %v", result["serverInfo"])
	}
	caps, ok := result["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities missing: %v", result)
	}
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("capabilities.tools missing: %v", caps)
	}
}

func TestInitializeDefaultsProtocolVersionWhenClientOmitsIt(t *testing.T) {
	got := serveOne(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	result := got[0]["result"].(map[string]any)
	if result["protocolVersion"] != protocolVersion {
		t.Fatalf("want fallback %q, got %v", protocolVersion, result["protocolVersion"])
	}
}

func TestToolsListShowsExactlyThreeToolsWithSchemas(t *testing.T) {
	got := serveOne(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	result := got[0]["result"].(map[string]any)
	tools, ok := result["tools"].([]any)
	if !ok || len(tools) != 3 {
		t.Fatalf("want 3 tools, got %v", result["tools"])
	}
	names := map[string]bool{}
	for _, raw := range tools {
		tool := raw.(map[string]any)
		name, _ := tool["name"].(string)
		names[name] = true
		if tool["description"] == "" || tool["description"] == nil {
			t.Fatalf("tool %s missing a description", name)
		}
		if _, ok := tool["inputSchema"].(map[string]any); !ok {
			t.Fatalf("tool %s missing inputSchema", name)
		}
	}
	for _, want := range []string{"list_handles", "run_with_secrets", "capture"} {
		if !names[want] {
			t.Fatalf("tools/list missing %q: %v", want, names)
		}
	}
}

func TestToolsCallUnknownToolIsError(t *testing.T) {
	got := serveOne(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	if _, ok := got[0]["error"].(map[string]any); !ok {
		t.Fatalf("want a JSON-RPC error for an unknown tool: %v", got[0])
	}
}

func TestPingReplies(t *testing.T) {
	got := serveOne(t, `{"jsonrpc":"2.0","id":7,"method":"ping"}`)
	if len(got) != 1 || got[0]["id"] != float64(7) {
		t.Fatalf("ping: %v", got)
	}
	if _, ok := got[0]["result"]; !ok {
		t.Fatalf("ping should return a result: %v", got[0])
	}
}

func TestMultipleRequestsGetMatchingIDsInOrder(t *testing.T) {
	got := serveOne(t,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled"}`,
		`{"jsonrpc":"2.0","id":"two","method":"ping"}`,
	)
	if len(got) != 2 {
		t.Fatalf("want 2 responses (notification produces none), got %d: %v", len(got), got)
	}
	if got[0]["id"] != float64(1) {
		t.Fatalf("first response id: %v", got[0]["id"])
	}
	if got[1]["id"] != "two" {
		t.Fatalf("second response id: %v", got[1]["id"])
	}
}
