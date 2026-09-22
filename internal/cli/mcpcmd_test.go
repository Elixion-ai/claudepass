package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

// mcpRequestLine marshals one JSON-RPC 2.0 request/notification line for
// driving cmdMCP's stdin directly, the same shape internal/mcp/server_test.go's
// serveOne feeds mcp.Serve.
func mcpRequestLine(t *testing.T, id any, method string, params any) string {
	t.Helper()
	req := map[string]any{"jsonrpc": "2.0", "method": method}
	if id != nil {
		req["id"] = id
	}
	if params != nil {
		req["params"] = params
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestMCPServeNeverEmitsANSIEvenWithTTYLookingColourMode is the regression
// test for cmdMCP (mcpcmd.go): unlike cmdRun and cmdCapture, it passes
// e.stdin/e.stdout/e.stderr straight to mcp.Serve and never wires this
// env's outMode/errMode markerDecorator into it at all — an MCP stdio
// client is never the human terminal docs/CLI-STYLE.md's Colour section
// describes. This must hold even when the destination stream would
// otherwise resolve to a real colour mode: here e.outMode and e.errMode
// are built through the same injectable detectColorMode(isTTY, getenv)
// every ansi_test.go case uses, with isTTY=true and COLORTERM=truecolor —
// exactly what a real terminal attached to cpass mcp's stdout would
// resolve to — so the JSON-RPC stream it drives must still carry zero
// 0x1b bytes anywhere, including inside a [REDACTED:...] marker produced
// by run_with_secrets.
func TestMCPServeNeverEmitsANSIEvenWithTTYLookingColourMode(t *testing.T) {
	home := t.TempDir()
	t.Setenv(broker.EnvHome, home)
	key := bytes.Repeat([]byte{0x11}, vault.KeySize)
	t.Setenv(broker.EnvKey, base64.StdEncoding.EncodeToString(key))
	vp, err := broker.VaultPath()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Create(vp, key)
	if err != nil {
		t.Fatal(err)
	}
	const secretValue = "sk_live_51H8xJ2eZvKYlo2CTmcpAnsiRegressionABCxyz"
	if _, err := v.Add("stripe/live", secretValue, vault.AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	// The injected command "cat"s a file carrying the raw value, rather
	// than referencing the bound $STRIPE_LIVE by name in argv/a shell
	// string: that would trip Command Policy's own refusal (see
	// TestRefuseMatchesGrammar's "echo would print a bound variable"
	// case), which isn't what this test is about. redact.Writer matches
	// by value, not by how the value reached the child's stdout, so this
	// still exercises the real redaction path run_with_secrets uses.
	leak := filepath.Join(t.TempDir(), "leak.txt")
	if err := os.WriteFile(leak, []byte(secretValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	lines := []string{
		mcpRequestLine(t, 1, "initialize", map[string]any{"protocolVersion": "2025-06-18"}),
		mcpRequestLine(t, nil, "notifications/initialized", nil),
		mcpRequestLine(t, 2, "tools/call", map[string]any{
			"name": "run_with_secrets",
			"arguments": map[string]any{
				"command": []string{"cat", leak},
				"handles": []string{"stripe/live"},
			},
		}),
	}

	var out, errb bytes.Buffer
	// isTTY=true + COLORTERM=truecolor is exactly TestDetectColorMode's
	// "TTY, COLORTERM=truecolor: 24-bit" case (ansi_test.go): colour would
	// be on for a real terminal in this mode.
	ttyLookingMode := detectColorMode(true, fakeEnv(map[string]string{"COLORTERM": "truecolor"}))
	if ttyLookingMode != colorTrue {
		t.Fatalf("test setup: detectColorMode(true, COLORTERM=truecolor) = %v, want colorTrue", ttyLookingMode)
	}
	e := &env{
		stdin:   strings.NewReader(strings.Join(lines, "\n") + "\n"),
		stdout:  &out,
		stderr:  &errb,
		outMode: ttyLookingMode,
		errMode: ttyLookingMode,
	}
	if code := cmdMCP(e); code != ExitOK {
		t.Fatalf("cmdMCP = %d, want ExitOK (%d); stderr=%s", code, ExitOK, errb.String())
	}

	raw := out.String()
	if containsESC(raw) {
		t.Fatalf("cpass mcp stdout leaked ANSI escapes: %q", raw)
	}
	if strings.Contains(raw, secretValue) {
		t.Fatalf("cpass mcp stdout leaked the raw Secret value: %q", raw)
	}
	if !strings.Contains(raw, "[REDACTED:stripe/live]") {
		t.Fatalf("cpass mcp stdout missing the plain redaction marker: %q", raw)
	}

	// Also check the tools/call response's own content text, the shape an
	// MCP client actually reads (see internal/mcp/tools.go's toolResult).
	var toolResultText string
	var sawToolResponse bool
	for _, line := range strings.Split(strings.TrimRight(raw, "\n"), "\n") {
		var resp struct {
			ID     json.Number `json:"id"`
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&resp); err != nil {
			t.Fatalf("bad response line %q: %v", line, err)
		}
		if resp.ID.String() != "2" {
			continue
		}
		sawToolResponse = true
		if resp.Result.IsError {
			t.Fatalf("run_with_secrets reported an error: %s", line)
		}
		for _, c := range resp.Result.Content {
			toolResultText += c.Text
		}
	}
	if !sawToolResponse {
		t.Fatalf("did not find the tools/call response for id 2 in: %q", raw)
	}
	if containsESC(toolResultText) {
		t.Fatalf("run_with_secrets tool result leaked ANSI escapes: %q", toolResultText)
	}
	if strings.Contains(toolResultText, secretValue) {
		t.Fatalf("run_with_secrets tool result leaked the raw Secret value: %q", toolResultText)
	}
	if !strings.Contains(toolResultText, "[REDACTED:stripe/live]") {
		t.Fatalf("run_with_secrets tool result missing the plain redaction marker: %q", toolResultText)
	}
}

// mcpInitializeServerVersion drives cmdMCP with a single initialize request
// and returns result.serverInfo.version from its response.
func mcpInitializeServerVersion(t *testing.T) string {
	t.Helper()
	var out, errb bytes.Buffer
	e := &env{
		stdin:  strings.NewReader(mcpRequestLine(t, 1, "initialize", map[string]any{"protocolVersion": "2025-06-18"}) + "\n"),
		stdout: &out,
		stderr: &errb,
	}
	if code := cmdMCP(e); code != ExitOK {
		t.Fatalf("cmdMCP = %d, want ExitOK (%d); stderr=%s", code, ExitOK, errb.String())
	}
	var resp struct {
		Result struct {
			ServerInfo struct {
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	line := strings.TrimSpace(out.String())
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("bad initialize response %q: %v", line, err)
	}
	return resp.Result.ServerInfo.Version
}

// TestMCPInitializeReportsEffectiveVersion is CLA-98 item 6's regression
// test: cmdMCP used to pass the raw Version package var straight to
// mcp.Serve, so a `go install .../cmd/cpass@<tag>` build — which only ever
// gets its version from runtime/debug.ReadBuildInfo's Main.Version, never
// from GoReleaser's ldflags (see effectiveVersion's own doc comment) —
// reported "dev" in the initialize response even though `cpass version`
// itself, which already goes through effectiveVersion, correctly named the
// real tag. Both cases mirror TestVersionFallsBackToBuildInfo's own two
// subtests, against the same injectable readBuildInfo.
func TestMCPInitializeReportsEffectiveVersion(t *testing.T) {
	origVersion, origReadBuildInfo := Version, readBuildInfo
	t.Cleanup(func() { Version, readBuildInfo = origVersion, origReadBuildInfo })

	t.Run("dev falls back to Main.Version from build info", func(t *testing.T) {
		Version = "dev"
		readBuildInfo = func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, true
		}
		if got := mcpInitializeServerVersion(t); got != "v1.2.3" {
			t.Fatalf("serverInfo.version = %q, want %q (effectiveVersion's build-info fallback)", got, "v1.2.3")
		}
	})

	t.Run("ldflags-injected Version wins over build info", func(t *testing.T) {
		Version = "v9.9.9"
		readBuildInfo = func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, true
		}
		if got := mcpInitializeServerVersion(t); got != "v9.9.9" {
			t.Fatalf("serverInfo.version = %q, want %q (the ldflags-injected Version)", got, "v9.9.9")
		}
	})
}
