package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// mcpSession drives `cpass mcp` as a live subprocess talking JSON-RPC 2.0
// over stdio: the exact boundary an MCP Agent uses. rawOut accumulates
// every byte the process ever writes to stdout — every JSON-RPC frame —
// so a test can assert a raw Secret value never appears anywhere in the
// stream, not only in the one response it happens to check.
type mcpSession struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	rawOut *syncBuffer
	stderr *bytes.Buffer
	nextID int
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startMCP launches `cpass mcp` against ve's Vault. extraEnv is appended to
// the process environment, e.g. to set HELPER_ECHO for helperBin.
func startMCP(t *testing.T, ve *vaultEnv, extraEnv ...string) *mcpSession {
	t.Helper()
	cmd := exec.Command(cpassBin, "mcp")
	cmd.Env = append(baseEnv(), "CPASS_HOME="+ve.home, "CPASS_KEY="+ve.key)
	cmd.Env = append(cmd.Env, extraEnv...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	raw := &syncBuffer{}
	s := &mcpSession{
		t: t, cmd: cmd, stdin: stdin, rawOut: raw, stderr: &stderr,
		reader: bufio.NewReaderSize(io.TeeReader(stdoutPipe, raw), 1<<20),
	}
	t.Cleanup(func() {
		_ = s.stdin.Close()
		_ = s.cmd.Wait()
	})
	return s
}

// call sends a JSON-RPC request with a fresh id and returns its result,
// failing the test on a malformed response or a JSON-RPC-level error.
func (s *mcpSession) call(method string, params any) json.RawMessage {
	s.t.Helper()
	s.nextID++
	id := s.nextID
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	s.write(req)
	line := s.readLine()
	var resp struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		s.t.Fatalf("bad response %q: %v", line, err)
	}
	if resp.ID != id {
		s.t.Fatalf("response id %d, want %d: %s", resp.ID, id, line)
	}
	if resp.Error != nil {
		s.t.Fatalf("%s: rpc error %d: %s", method, resp.Error.Code, resp.Error.Message)
	}
	return resp.Result
}

// notify sends a notification: no id, no response expected.
func (s *mcpSession) notify(method string) {
	s.write(map[string]any{"jsonrpc": "2.0", "method": method})
}

func (s *mcpSession) write(v any) {
	s.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		s.t.Fatal(err)
	}
	b = append(b, '\n')
	if _, err := s.stdin.Write(b); err != nil {
		s.t.Fatalf("write request: %v (stderr: %s)", err, s.stderr.String())
	}
}

func (s *mcpSession) readLine() []byte {
	s.t.Helper()
	line, err := s.reader.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		s.t.Fatalf("read response: %v (stderr: %s)", err, s.stderr.String())
	}
	return bytes.TrimSpace(line)
}

// initialize performs the standard handshake and returns the raw
// initialize result.
func (s *mcpSession) initialize() json.RawMessage {
	s.t.Helper()
	result := s.call("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "cpass-e2e", "version": "0"},
	})
	s.notify("notifications/initialized")
	return result
}

// callTool calls tools/call and returns its content blocks' text (the
// first block is always the tool's own JSON result; a second block, if
// present, carries redaction/Exposed notices — see run_with_secrets) and
// whether the result was marked isError.
func (s *mcpSession) callTool(name string, args any) (text []string, isError bool) {
	s.t.Helper()
	raw := s.call("tools/call", map[string]any{"name": name, "arguments": args})
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		s.t.Fatalf("bad tool result %q: %v", raw, err)
	}
	for _, c := range result.Content {
		text = append(text, c.Text)
	}
	return text, result.IsError
}

// callToolText is callTool for the common case: exactly one content block.
func (s *mcpSession) callToolText(name string, args any) (text string, isError bool) {
	s.t.Helper()
	parts, isError := s.callTool(name, args)
	return strings.Join(parts, "\n"), isError
}

func TestMCPInitializeHandshake(t *testing.T) {
	ve := newVault(t)
	s := startMCP(t, ve)
	raw := s.initialize()
	var res struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
		Capabilities struct {
			Tools map[string]any `json:"tools"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	if res.ProtocolVersion != "2025-06-18" {
		t.Fatalf("protocolVersion not negotiated: %s", res.ProtocolVersion)
	}
	if res.ServerInfo.Name != "claudepass" {
		t.Fatalf("serverInfo.name: %s", res.ServerInfo.Name)
	}
	if res.Capabilities.Tools == nil {
		t.Fatalf("capabilities.tools missing: %s", raw)
	}
}

func TestMCPToolsListShowsThreeTools(t *testing.T) {
	ve := newVault(t)
	s := startMCP(t, ve)
	s.initialize()
	raw := s.call("tools/list", nil)
	var res struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 3 {
		t.Fatalf("want 3 tools, got %d: %s", len(res.Tools), raw)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
		if tool.Description == "" || tool.InputSchema == nil {
			t.Fatalf("tool %s missing description/inputSchema: %s", tool.Name, raw)
		}
	}
	for _, want := range []string{"list_handles", "run_with_secrets", "capture"} {
		if !names[want] {
			t.Fatalf("tools/list missing %q: %s", want, raw)
		}
	}
}

// TestMCPRunWithSecretsSucceedsAndRedacts mirrors the CLI leak-suite
// pattern (TestCaptureWithInjectsOtherHandles): HELPER_ECHO is set on the
// process environment, not in argv, so Command Policy sees nothing to
// refuse and Redaction alone must catch the value on its way out.
func TestMCPRunWithSecretsSucceedsAndRedacts(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", secret)
	s := startMCP(t, ve, "HELPER_ECHO=wrapped-$STRIPE_LIVE")
	s.initialize()
	parts, isError := s.callTool("run_with_secrets", map[string]any{
		"command": []string{helperBin},
		"handles": []string{"stripe/live"},
	})
	if isError {
		t.Fatalf("run_with_secrets reported an error: %v", parts)
	}
	var out struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(parts[0]), &out); err != nil {
		t.Fatalf("bad result %q: %v", parts[0], err)
	}
	// A redaction notice is the expected second content block: it names
	// the Handle and count, never the value.
	if len(parts) > 1 && strings.Contains(parts[1], secret) {
		t.Fatalf("redaction notice leaked the raw value: %s", parts[1])
	}
	if out.ExitCode != 0 {
		t.Fatalf("exit_code: %d (stderr %q)", out.ExitCode, out.Stderr)
	}
	if strings.Contains(out.Stdout, secret) {
		t.Fatalf("raw value in stdout: %s", out.Stdout)
	}
	if !strings.Contains(out.Stdout, "[REDACTED:stripe/live]") {
		t.Fatalf("marker missing from stdout: %q", out.Stdout)
	}
}

func TestMCPRunWithSecretsRefusesCommandPolicyViolation(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", secret)
	s := startMCP(t, ve)
	s.initialize()
	text, isError := s.callToolText("run_with_secrets", map[string]any{
		"command": []string{"env"},
		"handles": []string{"stripe/live"},
	})
	if !isError {
		t.Fatalf("want a Command Policy refusal, got success: %s", text)
	}
	if !strings.Contains(text, "refused") {
		t.Fatalf("refusal message: %s", text)
	}
	if strings.Contains(text, secret) || strings.Contains(s.rawOut.String(), secret) {
		t.Fatalf("refused command leaked the value: %s", text)
	}
}

// TestMCPRunWithSecretsRefusesSecretFileRead is CLA-38's MCP proof that
// run_with_secrets refuses reading a .env-style file directly, the same
// rule `cpass policy --hook` already applied and cpass run now also
// applies — see TestPolicyRunRefusesSecretFileReadsAndRawLiterals in
// policy_test.go for the CLI side of this same parity fix.
func TestMCPRunWithSecretsRefusesSecretFileRead(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", secret)
	s := startMCP(t, ve)
	s.initialize()
	text, isError := s.callToolText("run_with_secrets", map[string]any{
		"command": []string{"cat", ".env"},
		"handles": []string{"stripe/live"},
	})
	if !isError {
		t.Fatalf("want a Command Policy refusal, got success: %s", text)
	}
	if !strings.Contains(text, "refused") || !strings.Contains(text, "Secret-bearing file") {
		t.Fatalf("refusal message should name the Secret-bearing file rule: %s", text)
	}
	if strings.Contains(text, secret) || strings.Contains(s.rawOut.String(), secret) {
		t.Fatalf("refused command leaked the value: %s", text)
	}

	// Keep an ordinary, unrelated file read allowed.
	text, isError = s.callToolText("run_with_secrets", map[string]any{
		"command": []string{"cat", "/etc/hosts"},
		"handles": []string{"stripe/live"},
	})
	if isError {
		t.Fatalf("cat /etc/hosts should be allowed: %s", text)
	}
}

func TestMCPCaptureThenListHandles(t *testing.T) {
	ve := newVault(t)
	s := startMCP(t, ve)
	s.initialize()
	text, isError := s.callToolText("capture", map[string]any{
		"handle":  "demo/token",
		"command": []string{"sh", "-c", "echo tok_abcdef123456"},
	})
	if isError {
		t.Fatalf("capture reported an error: %s", text)
	}
	var captured struct {
		Handle string `json:"handle"`
	}
	if err := json.Unmarshal([]byte(text), &captured); err != nil {
		t.Fatalf("bad capture result %q: %v", text, err)
	}
	if captured.Handle != "demo/token" {
		t.Fatalf("handle: %s", captured.Handle)
	}
	if strings.Contains(text, "tok_") {
		t.Fatalf("captured value leaked in tool result: %s", text)
	}

	listText, isError := s.callToolText("list_handles", map[string]any{})
	if isError {
		t.Fatalf("list_handles reported an error: %s", listText)
	}
	var listed struct {
		Handles []string `json:"handles"`
	}
	if err := json.Unmarshal([]byte(listText), &listed); err != nil {
		t.Fatalf("bad list_handles result %q: %v", listText, err)
	}
	found := false
	for _, h := range listed.Handles {
		if h == "demo/token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("demo/token not listed: %v", listed.Handles)
	}
	if strings.Contains(s.rawOut.String(), "tok_abcdef123456") {
		t.Fatal("raw captured value appeared in a JSON-RPC frame")
	}
}

func TestMCPCaptureRejectsExistingHandle(t *testing.T) {
	ve := newVault(t)
	ve.add("demo/token", "already-here-value")
	s := startMCP(t, ve)
	s.initialize()
	text, isError := s.callToolText("capture", map[string]any{
		"handle":  "demo/token",
		"command": []string{"sh", "-c", "echo tok_abcdef123456"},
	})
	if !isError || !strings.Contains(text, "already exists") {
		t.Fatalf("want a collision error: %s", text)
	}
}

// TestMCPCaptureRedactsCpassKeyFromStderr is CLA-54's MCP-side regression
// test: callCapture (internal/mcp/tools.go) opens the Vault itself via its
// own broker.OpenVault() call before run.Run ever runs, and the capture
// tool has no --with-equivalent field at all, so Refs is always empty here
// -- the shape the old guard (len(spec.Refs) > 0) could never satisfy on
// this surface, on every single invocation, not just the common case.
//
// callCapture does not currently forward the wrapped command's stderr into
// the tool's JSON-RPC result at all (unlike run_with_secrets, which does
// via its warn content block) — so this raw value has nowhere to leak to
// *today* regardless of this guard, and this assertion holds even
// unfixed. It is still asserted here, alongside
// TestRunRegistersCpassKeyPatternWithEmptyRefs (run_test.go), which pins
// the actual guard fix directly against Run's Spec (the exact shape this
// call site produces) and does fail on the unfixed guard — so that this
// test keeps catching a real leak if callCapture is ever changed to
// surface stderr the way run_with_secrets already does.
func TestMCPCaptureRedactsCpassKeyFromStderr(t *testing.T) {
	ve := newVault(t)
	s := startMCP(t, ve)
	s.initialize()
	script := `printf 'RAWKEY=[%s]\n' '` + ve.key + `' 1>&2; echo capture-body-value-1`
	text, isError := s.callToolText("capture", map[string]any{
		"handle":  "demo/token",
		"command": []string{"sh", "-c", script},
	})
	if isError {
		t.Fatalf("capture reported an error: %s", text)
	}
	if strings.Contains(s.rawOut.String(), ve.key) {
		t.Fatal("CPASS_KEY value leaked in the JSON-RPC stream")
	}
}

// TestMCPRunWithSecretsStripsCpassKeyFromChild is CLA-98 item 2's
// regression test for the MCP-side half of CLA-54's acceptance criterion,
// which named both `cpass run` and MCP `run_with_secrets` but only ever
// got a test for the CLI path (TestRunStripsCpassKeyFromChild, e2e). It
// drives run_with_secrets the same way: startMCP sets CPASS_KEY on the
// `cpass mcp` process's own environment (its unlock source, exactly like a
// CI/unattended `cpass run`), and the child — launched via run_with_secrets
// rather than `cpass run` — dumps its own environment to a file with the
// helper binary's existing HELPER_OUT pattern, never to stdout, so a
// leaked value could never round-trip through the JSON-RPC stream even if
// this assertion missed it. Runs with zero handles, matching the CLI
// test's zero-`--with` case: the strip must not depend on any Handle
// actually being resolved.
func TestMCPRunWithSecretsStripsCpassKeyFromChild(t *testing.T) {
	ve := newVault(t)
	out := filepath.Join(t.TempDir(), "env.txt")
	s := startMCP(t, ve, "HELPER_OUT="+out)
	s.initialize()
	parts, isError := s.callTool("run_with_secrets", map[string]any{
		"command": []string{helperBin},
	})
	if isError {
		t.Fatalf("run_with_secrets reported an error: %v", parts)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read helper env dump: %v", err)
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			env[k] = v
		}
	}
	if v, ok := env["CPASS_KEY"]; ok && v != "" {
		t.Fatalf("child saw CPASS_KEY=%q via run_with_secrets: %v", v, env)
	}
	if env["CPASS_HOME"] != ve.home {
		t.Fatalf("CPASS_HOME is a mode selector, not a Secret, and must still reach the child: %v", env)
	}
}

func TestMCPRunWithSecretsUsesManifestWhenHandlesOmitted(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one")
	repo := t.TempDir()
	if r := ve.runIn(repo, nil, "manifest", "init"); r.code != 0 {
		t.Fatalf("manifest init: %s", r)
	}
	if r := ve.runIn(repo, nil, "manifest", "add", "a/one"); r.code != 0 {
		t.Fatalf("manifest add: %s", r)
	}
	s := startMCP(t, ve)
	s.initialize()
	text, isError := s.callToolText("run_with_secrets", map[string]any{
		"command": []string{"sh", "-c", "echo present-$A_ONE" + "-ok"},
		"cwd":     repo,
	})
	// The bound variable is referenced in a shell echo, so Command Policy
	// refuses it — proving the Manifest's Handle really was resolved and
	// bound (an unbound A_ONE would not trip the refusal at all).
	if !isError || !strings.Contains(text, "refused") {
		t.Fatalf("want a policy refusal proving the Manifest handle was bound: %s", text)
	}
}

func TestMCPCommandRejectsExtraArgs(t *testing.T) {
	ve := newVault(t)
	r := ve.run(nil, "mcp", "extra")
	if r.code != 2 || !strings.Contains(r.stderr, "usage") {
		t.Fatalf("want usage error: %s", r)
	}
}

// TestMCPRawValueNeverInAnyFrame drives a full session — initialize,
// tools/list, a successful run_with_secrets, a refused one, a capture, and
// a list_handles — and asserts the raw value of every Secret involved is
// absent from every byte the server ever wrote to stdout across the whole
// session, not only from the one response each other test happens to
// check.
func TestMCPRawValueNeverInAnyFrame(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", secret)
	s := startMCP(t, ve, "HELPER_ECHO=wrapped-$STRIPE_LIVE")
	s.initialize()
	s.call("tools/list", nil)
	s.callTool("run_with_secrets", map[string]any{"command": []string{helperBin}, "handles": []string{"stripe/live"}})
	s.callTool("run_with_secrets", map[string]any{"command": []string{"env"}, "handles": []string{"stripe/live"}})
	s.callTool("capture", map[string]any{"handle": "demo/token", "command": []string{"sh", "-c", "echo tok_abcdef123456"}})
	s.callTool("list_handles", map[string]any{})

	all := s.rawOut.String()
	if strings.Contains(all, secret) {
		t.Fatal("raw Secret value appeared in the JSON-RPC stream")
	}
	if strings.Contains(all, "tok_abcdef123456") {
		t.Fatal("raw captured value appeared in the JSON-RPC stream")
	}
	if !strings.Contains(all, "[REDACTED:stripe/live]") {
		t.Fatal("redaction marker missing from the stream")
	}
}

// TestMCPRunWithSecretsInjectsGlobalHandles covers the surface the Global
// Manifest exists for: an Agent's session reaches cpass through this tool,
// not through the CLI, so a Handle that does not arrive here does not arrive
// at all.
func TestMCPRunWithSecretsInjectsGlobalHandles(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one", "-g")
	repo := t.TempDir()
	if r := ve.runIn(repo, nil, "manifest", "init"); r.code != 0 {
		t.Fatalf("manifest init: %s", r)
	}
	s := startMCP(t, ve)
	s.initialize()
	// The project declares nothing; only the Global Manifest names a/one.
	// As above, Command Policy refusing the shell echo is the proof that the
	// variable really was bound — an unbound A_ONE would not trip it.
	text, isError := s.callToolText("run_with_secrets", map[string]any{
		"command": []string{"sh", "-c", "echo present-$A_ONE" + "-ok"},
		"cwd":     repo,
	})
	if !isError || !strings.Contains(text, "refused") {
		t.Fatalf("want a refusal proving the Global Handle was bound: %s", text)
	}
	// no_global takes it back out, so the same call is no longer refused.
	text, isError = s.callToolText("run_with_secrets", map[string]any{
		"command":   []string{"sh", "-c", "echo present-$A_ONE" + "-ok"},
		"cwd":       repo,
		"no_global": true,
	})
	if isError {
		t.Fatalf("no_global should leave nothing bound to refuse: %s", text)
	}
}

// TestMCPRunWithSecretsSaysWhenCwdWasGuessed: this server is one long-lived
// process whose working directory never follows the Agent's, so a call that
// names no cwd resolved its Manifest somewhere the caller did not choose.
// That is invisible unless it is said out loud.
func TestMCPRunWithSecretsSaysWhenCwdWasGuessed(t *testing.T) {
	ve := newVault(t)
	s := startMCP(t, ve)
	s.initialize()
	text, isError := s.callToolText("run_with_secrets", map[string]any{
		"command": []string{"true"},
	})
	if isError {
		t.Fatalf("run: %s", text)
	}
	if !strings.Contains(text, "no cwd given") || !strings.Contains(text, "pass cwd") {
		t.Fatalf("want the ambiguous-cwd advisory: %s", text)
	}
	// Naming a cwd removes the advisory entirely.
	text, isError = s.callToolText("run_with_secrets", map[string]any{
		"command": []string{"true"},
		"cwd":     t.TempDir(),
	})
	if isError || strings.Contains(text, "no cwd given") {
		t.Fatalf("an explicit cwd must not be warned about: %s", text)
	}
}

// TestMCPListHandlesFiltersToGlobal keeps the Agent's own view of which
// Handles are ambient in step with `cpass ls --global`.
func TestMCPListHandlesFiltersToGlobal(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one", "-g")
	ve.add("b/two", "value-number-two")
	s := startMCP(t, ve)
	s.initialize()
	text, isError := s.callToolText("list_handles", map[string]any{"global": true})
	if isError {
		t.Fatalf("list_handles: %s", text)
	}
	if !strings.Contains(text, "a/one") || strings.Contains(text, "b/two") {
		t.Fatalf("global filter: %s", text)
	}
	text, _ = s.callToolText("list_handles", map[string]any{})
	if !strings.Contains(text, "a/one") || !strings.Contains(text, "b/two") {
		t.Fatalf("unfiltered listing must show both: %s", text)
	}
}

// TestMCPCancelledRunWithSecretsUnblocksQueuedPing is CLA-76's repro: a
// sleep-wrapped run_with_secrets call, a notifications/cancelled for it,
// then a ping, sent back to back with none of their responses read in
// between (the exact ordering that used to leave the cancellation and the
// ping both sitting unread on stdin until the blocking call finished on its
// own). It asserts two separate things the fix promises: the ping's
// response arrives long before the sleep would finish on its own (the read
// loop was never blocked behind it), and the cancelled call never gets a
// response at all — per the MCP Cancellation spec — and its child was
// actually killed rather than left to finish in the background.
func TestMCPCancelledRunWithSecretsUnblocksQueuedPing(t *testing.T) {
	ve := newVault(t)
	s := startMCP(t, ve)
	s.initialize()

	marker := filepath.Join(t.TempDir(), "marker")
	s.nextID++
	sleepID := s.nextID
	s.write(map[string]any{
		"jsonrpc": "2.0", "id": sleepID, "method": "tools/call",
		"params": map[string]any{
			"name": "run_with_secrets",
			"arguments": map[string]any{
				"command": []string{"sh", "-c", "sleep 3 && touch " + marker},
			},
		},
	})
	s.write(map[string]any{
		"jsonrpc": "2.0", "method": "notifications/cancelled",
		"params": map[string]any{"requestId": sleepID},
	})

	start := time.Now()
	s.call("ping", nil)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("ping took %s: the sleep-wrapped call still blocked the read loop", elapsed)
	}

	// Give the child's own 3s sleep well past enough time to have finished
	// and touched marker if it were still running unattended, then check it
	// never did — proof the cancellation actually killed it rather than
	// merely detaching from it — and that no response ever arrived for
	// sleepID, per the MCP Cancellation spec.
	time.Sleep(4 * time.Second)
	for _, line := range bytes.Split(bytes.TrimSpace([]byte(s.rawOut.String())), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var m struct {
			ID any `json:"id"`
		}
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		if id, ok := m.ID.(float64); ok && int(id) == sleepID {
			t.Fatalf("cancelled request got a response, want none: %s", line)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("child process kept running after cancellation instead of being killed")
	}
}

// TestMCPKeychainUnlockKeyIsCachedAcrossCalls is CLA-77's acceptance
// benchmark: on the real macOS Keychain path (no CPASS_KEY), the first
// list_handles call pays UnlockKey()'s `security` subprocess cost, and
// every call after it must be dramatically cheaper — served from the
// server's cached key rather than shelling out again. A unique
// CPASS_KEYCHAIN_SERVICE means this never touches a real "cpass" Keychain
// item, and the item is deleted when the test ends (see
// TestKeychainUnlockRoundTrip in unlock_test.go, the existing pattern this
// follows).
func TestMCPKeychainUnlockKeyIsCachedAcrossCalls(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Keychain unlock is macOS-only")
	}
	service := fmt.Sprintf("cpass-e2e-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	ve := lockedVault(t)
	env := []string{"CPASS_KEYCHAIN_SERVICE=" + service}
	t.Cleanup(func() {
		_ = exec.Command("security", "delete-generic-password", "-a", ve.vaultPath(), "-s", service).Run() // best-effort cleanup
	})
	if r := ve.runEnv(env, nil, "init"); r.code != 0 {
		t.Fatalf("init: %s", r)
	}

	cmd := exec.Command(cpassBin, "mcp")
	cmd.Env = append(baseEnv(), "CPASS_HOME="+ve.home) // deliberately no CPASS_KEY: exercise the Keychain
	cmd.Env = append(cmd.Env, env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	raw := &syncBuffer{}
	s := &mcpSession{
		t: t, cmd: cmd, stdin: stdin, rawOut: raw, stderr: &stderr,
		reader: bufio.NewReaderSize(io.TeeReader(stdoutPipe, raw), 1<<20),
	}
	t.Cleanup(func() {
		_ = s.stdin.Close()
		_ = s.cmd.Wait()
	})
	s.initialize()

	const calls = 10
	var latencies [calls]time.Duration
	for i := range latencies {
		start := time.Now()
		text, isError := s.callToolText("list_handles", map[string]any{})
		latencies[i] = time.Since(start)
		if isError {
			t.Fatalf("list_handles call %d: %s", i, text)
		}
	}

	first := latencies[0]
	var restTotal time.Duration
	for _, d := range latencies[1:] {
		restTotal += d
	}
	restAvg := restTotal / time.Duration(len(latencies)-1)
	t.Logf("first call %s, average of the other %d calls %s", first, len(latencies)-1, restAvg)
	// The gap this asserts on (first call pays one `security` subprocess,
	// ~15ms; a cached call is sub-millisecond — CLA-77's own measurement)
	// is roughly 24x, so a generous fraction of the first call still leaves
	// a wide, load-tolerant margin against the always-fresh, uncached
	// behaviour this is a regression test for.
	if restAvg > first/3 {
		t.Fatalf("later calls (avg %s) were not meaningfully cheaper than the first (%s): the unlock key does not look cached", restAvg, first)
	}
}

// TestMCPConcurrentCapturesAllSurvive is CLA-76's own regression test.
// callAsync (cancel.go) makes run_with_secrets/capture run in their own
// goroutine so a slow child never blocks the stdin read loop — which means
// a real MCP client, which never has to wait for one response before
// sending the next request, can now have two capture calls genuinely
// in flight in this process at once. Nothing before vault.Update's file
// lock (which replaced an interim in-process mutex) serialized callCapture's Open -> mutate -> Save cycle across that new
// concurrency, so two overlapping captures raced vault.go's fixed
// vault.cpv.tmp path and each other's in-memory Vault snapshot: silently
// losing a handle, a hard rename error, or (worst case) a corrupted Vault.
// Fired back-to-back with a short sleep in each child so their post-sleep
// Add/Save calls land close together, this reliably reproduced the loss on
// the unfixed code; run with -race, which also catches any bare data race
// the fix might introduce, not just the corruption itself.
func TestMCPConcurrentCapturesAllSurvive(t *testing.T) {
	ve := newVault(t)
	s := startMCP(t, ve)
	s.initialize()

	const n = 6
	ids := make([]int, n)
	for i := 0; i < n; i++ {
		s.nextID++
		ids[i] = s.nextID
		s.write(map[string]any{
			"jsonrpc": "2.0", "id": ids[i], "method": "tools/call",
			"params": map[string]any{
				"name": "capture",
				"arguments": map[string]any{
					"handle":  fmt.Sprintf("race/handle-%d", i),
					"command": []string{"sh", "-c", fmt.Sprintf("sleep 0.05; echo captured-value-%d", i)},
				},
			},
		})
	}

	type callResult struct {
		text    string
		isError bool
	}
	results := make(map[int]callResult, n)
	for i := 0; i < n; i++ {
		line := s.readLine()
		var resp struct {
			ID     int `json:"id"`
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
				IsError bool `json:"isError"`
			} `json:"result"`
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			t.Fatalf("bad response %q: %v", line, err)
		}
		if resp.Error != nil {
			t.Fatalf("capture id %d: rpc error %d: %s", resp.ID, resp.Error.Code, resp.Error.Message)
		}
		text := ""
		if len(resp.Result.Content) > 0 {
			text = resp.Result.Content[0].Text
		}
		results[resp.ID] = callResult{text: text, isError: resp.Result.IsError}
	}
	for i, id := range ids {
		r, ok := results[id]
		if !ok {
			t.Fatalf("no response for capture %d (handle race/handle-%d)", id, i)
		}
		if r.isError {
			t.Fatalf("capture %d (race/handle-%d) reported an error: %s", id, i, r.text)
		}
	}

	listText, isError := s.callToolText("list_handles", map[string]any{})
	if isError {
		t.Fatalf("list_handles reported an error: %s", listText)
	}
	var listed struct {
		Handles []string `json:"handles"`
	}
	if err := json.Unmarshal([]byte(listText), &listed); err != nil {
		t.Fatalf("bad list_handles result %q: %v", listText, err)
	}
	have := map[string]bool{}
	for _, h := range listed.Handles {
		have[h] = true
	}
	for i := 0; i < n; i++ {
		want := fmt.Sprintf("race/handle-%d", i)
		if !have[want] {
			t.Fatalf("handle %s missing after %d concurrent captures: got %v", want, n, listed.Handles)
		}
	}
}
