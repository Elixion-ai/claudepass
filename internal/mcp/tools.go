package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/manifest"
	"github.com/Elixion-ai/claudepass/internal/run"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

// toolDef is one entry of a tools/list response.
type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

var toolDefs = []toolDef{
	{
		Name:        "list_handles",
		Description: "List Handle names in the Vault (never values), optionally filtered by a prefix or to those declared in the Global Manifest.",
		InputSchema: schema(map[string]any{
			"prefix": prop("string", "only Handles starting with this prefix"),
			"global": prop("boolean", "only Handles declared in the Global Manifest (injected into every project that has its own Manifest)"),
		}, nil),
	},
	{
		Name: "run_with_secrets",
		Description: "Run a command with Secrets injected by the Broker: the same execution path as `cpass run` " +
			"(Redaction, Command Policy, file Bindings). Uses the project Manifest and the Global Manifest when " +
			"handles is omitted. Always pass cwd: this server is one long-lived process whose own working " +
			"directory does not follow yours, and it is what decides which Manifest is found. " +
			"Returns the command's redacted stdout and stderr and its exit code; the raw value of a Secret never " +
			"appears in the result.",
		InputSchema: schema(map[string]any{
			"command":   arrayOfStrings(`argv to run, e.g. ["psql", "-c", "select 1"]`, 1),
			"handles":   arrayOfStrings(`Handles to inject, each "handle" or "handle:BINDING"; omit to use the project Manifest plus the Global Manifest`, 0),
			"cwd":       prop("string", "working directory for the command and for locating the Manifest; pass it on every call"),
			"no_global": prop("boolean", "skip the Global Manifest's Handles for this call"),
		}, []string{"command"}),
	},
	{
		Name: "capture",
		Description: "Run a command and store its stdout as a new Secret under handle, the same as `cpass capture`. " +
			"Returns the Handle only; the value never appears in the result.",
		InputSchema: schema(map[string]any{
			"handle":  prop("string", `Handle to create, e.g. "stripe/live"`),
			"command": arrayOfStrings("argv to run", 1),
			"cwd":     prop("string", "working directory for the command"),
		}, []string{"handle", "command"}),
	},
}

func schema(props map[string]any, required []string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(t, desc string) map[string]any { return map[string]any{"type": t, "description": desc} }

func arrayOfStrings(desc string, minItems int) map[string]any {
	m := map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
	if minItems > 0 {
		m["minItems"] = minItems
	}
	return m
}

func (s *server) handleToolsList(req request) {
	s.writeResult(req.ID, map[string]any{"tools": toolDefs})
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *server) handleToolsCall(req request) {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		s.writeError(req.ID, -32602, "invalid params: "+err.Error())
		return
	}
	switch p.Name {
	case "list_handles":
		s.callListHandles(req.ID, p.Arguments)
	case "run_with_secrets":
		id, args := req.ID, p.Arguments
		s.callAsync(id, func(cancel <-chan struct{}) { s.callRunWithSecrets(id, args, cancel) })
	case "capture":
		id, args := req.ID, p.Arguments
		s.callAsync(id, func(cancel <-chan struct{}) { s.callCapture(id, args, cancel) })
	default:
		s.writeError(req.ID, -32602, "unknown tool: "+p.Name)
	}
}

// toolResult is a CallToolResult. isError marks a tool-level failure
// (Command Policy refusal, missing Handle, nonzero exit, ...) as distinct
// from a JSON-RPC protocol error: the call reached the tool and the tool
// has something to say about why it didn't do what was asked, which the
// Agent needs to see and can react to, the same way a nonzero exit or a
// Command Policy refusal from `cpass run` is not a crash.
type toolResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(isError bool, text string) toolResult {
	return toolResult{Content: []contentBlock{{Type: "text", Text: text}}, IsError: isError}
}

// jsonResult renders v as the tool's one text content block. Every
// successful tool call in this server returns a small JSON object this way,
// so a caller always parses the same shape it would from the CLI's own
// machine-readable output.
func jsonResult(v any) toolResult {
	b, err := json.Marshal(v)
	if err != nil {
		return textResult(true, err.Error())
	}
	return textResult(false, string(b))
}

// --- list_handles ---

type listHandlesArgs struct {
	Prefix string `json:"prefix"`
	Global bool   `json:"global"`
}

func (s *server) callListHandles(id json.RawMessage, raw json.RawMessage) {
	var a listHandlesArgs
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &a); err != nil {
			s.writeError(id, -32602, "invalid arguments: "+err.Error())
			return
		}
	}
	v, err := s.keyCache.OpenVault() // CLA-77: reuse this server's cached key
	if err != nil {
		s.writeResult(id, textResult(true, err.Error()))
		return
	}
	// Only read when the caller actually asked about the Global Manifest: an
	// ordinary listing must not start depending on that file being readable.
	gm := &manifest.Manifest{}
	if a.Global {
		if gm, err = manifest.LoadGlobal(); err != nil {
			s.writeResult(id, textResult(true, err.Error()))
			return
		}
	}
	names := []string{}
	for _, e := range v.List(a.Prefix) {
		if a.Global && !gm.Has(e.Handle) {
			continue
		}
		names = append(names, e.Handle)
	}
	s.writeResult(id, jsonResult(map[string]any{"handles": names}))
}

// --- run_with_secrets ---

type runArgs struct {
	Command  []string  `json:"command"`
	Handles  *[]string `json:"handles"`
	Cwd      string    `json:"cwd"`
	NoGlobal bool      `json:"no_global"`
}

// callRunWithSecrets runs in its own goroutine (see callAsync in cancel.go)
// so a slow child does not block the stdin read loop; cancel is that
// call's own run.Spec.Cancel, closed by a matching notifications/cancelled
// (handleCancelled, cancel.go) to kill the child early. Every response
// this writes still goes through writeResult/writeError exactly as if it
// ran synchronously — those already drop it if cancel fired (see
// suppressed in cancel.go) — so nothing below needs to check cancel itself.
func (s *server) callRunWithSecrets(id json.RawMessage, raw json.RawMessage, cancel <-chan struct{}) {
	var a runArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		s.writeError(id, -32602, "invalid arguments: "+err.Error())
		return
	}
	if len(a.Command) == 0 {
		s.writeError(id, -32602, "command must be a non-empty array")
		return
	}
	refs, notices, ambiguousCwd, err := resolveRefs(a.Handles, a.Cwd, a.NoGlobal)
	if err != nil {
		s.writeResult(id, textResult(true, err.Error()))
		return
	}
	var stdout, stderr, warn bytes.Buffer
	for _, n := range notices {
		warn.WriteString(n + "\n")
	}
	if ambiguousCwd {
		// This server is one process for the whole session and its own
		// working directory never follows the Agent's. With no cwd to go on,
		// the Manifest — and so every Global Handle — was looked up
		// somewhere the caller did not name, which is silent and invisible
		// unless it is said out loud. Written into the warn buffer so it
		// rides the content block that already exists for notices.
		warn.WriteString("cpass: no cwd given, so the Manifest was located from this MCP server's own working directory, not yours; pass cwd to be sure which project's Handles (and Global Handles) are injected\n")
	}
	code, err := run.Run(run.Spec{
		Refs: refs, Argv: a.Command, Dir: a.Cwd,
		Stdout: &stdout, Stderr: &stderr, Warn: &warn,
		// UnsafeAllow is always false: an MCP client is never the human
		// terminal that --unsafe-allow requires, so Command Policy always
		// applies here, the same as an Agent-invoked `cpass run`.
		Resolver: s.keyCache.Resolve, // CLA-77: reuse this server's cached key
		Cancel:   cancel,             // CLA-76: notifications/cancelled kills the child
	})
	if err != nil {
		if errors.Is(err, run.ErrNoCommand) {
			s.writeError(id, -32602, err.Error())
			return
		}
		// Broker resolution failures (locked Vault, missing Handle) and
		// Command Policy refusals both land here as tool-level errors: the
		// call was well-formed, it just could not be satisfied.
		s.writeResult(id, textResult(true, err.Error()))
		return
	}
	result := jsonResult(map[string]any{
		"stdout":    stdout.String(),
		"stderr":    stderr.String(),
		"exit_code": code,
	})
	if warn.Len() > 0 {
		result.Content = append(result.Content, contentBlock{Type: "text", Text: strings.TrimRight(warn.String(), "\n")})
	}
	s.writeResult(id, result)
}

// resolveRefs builds the Refs for run_with_secrets: the explicit handles
// list when given (even an empty one — "run with nothing injected" is a
// legitimate request, and a Global Handle never sneaks into one), or
// manifest.Refs when omitted, exactly the Handle source `cpass run` uses
// with no --with flags.
//
// ambiguousCwd reports that the Manifest was located relative to this
// server process's own working directory because the caller named none. It
// does not depend on how many Refs came back: resolving against the wrong
// project is as wrong when it finds Handles as when it finds none.
func resolveRefs(handles *[]string, cwd string, noGlobal bool) (refs []broker.Ref, notices []string, ambiguousCwd bool, err error) {
	if handles != nil {
		refs := make([]broker.Ref, 0, len(*handles))
		for _, h := range *handles {
			r, err := broker.ParseRef(h)
			if err != nil {
				return nil, nil, false, err
			}
			refs = append(refs, r)
		}
		return refs, nil, false, nil
	}
	dir := cwd
	if dir == "" {
		dir = "."
	}
	refs, notices, err = manifest.Refs(dir, !noGlobal)
	return refs, notices, cwd == "", err
}

// --- capture ---

type captureArgs struct {
	Handle  string   `json:"handle"`
	Command []string `json:"command"`
	Cwd     string   `json:"cwd"`
}

// callCapture runs in its own goroutine (see callAsync in cancel.go) so a
// slow child does not block the stdin read loop; cancel is documented on
// callRunWithSecrets above and behaves identically here. Its own Vault
// write — the only one any tool here makes — is serialized against every
// other concurrent write tool call by s.vaultMu (server.go, CLA-76): see
// that section below for why.
func (s *server) callCapture(id json.RawMessage, raw json.RawMessage, cancel <-chan struct{}) {
	var a captureArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		s.writeError(id, -32602, "invalid arguments: "+err.Error())
		return
	}
	if err := vault.ValidateHandle(a.Handle); err != nil {
		s.writeResult(id, textResult(true, err.Error()))
		return
	}
	if len(a.Command) == 0 {
		s.writeError(id, -32602, "command must be a non-empty array")
		return
	}
	// Fail fast, before running argv, and reject the common case of an
	// already-used Handle without holding vaultMu across a child process of
	// arbitrary duration. This read is not itself race-free against another
	// concurrent capture — see the locked, re-checked Open/Add/Save below
	// (CLA-76), which is.
	precheck, err := s.keyCache.OpenVault() // CLA-77: reuse this server's cached key
	if err != nil {
		s.writeResult(id, textResult(true, err.Error()))
		return
	}
	if _, err := precheck.Get(a.Handle); err == nil {
		s.writeResult(id, textResult(true, fmt.Sprintf("handle %s already exists", a.Handle)))
		return
	}
	var stdout, stderr, warn bytes.Buffer
	code, err := run.Run(run.Spec{
		Argv: a.Command, Dir: a.Cwd, RawStdout: true,
		Stdout: &stdout, Stderr: &stderr, Warn: &warn,
		Cancel: cancel, // CLA-76: notifications/cancelled kills the child
	})
	if err != nil {
		if errors.Is(err, run.ErrNoCommand) {
			s.writeError(id, -32602, err.Error())
			return
		}
		s.writeResult(id, textResult(true, err.Error()))
		return
	}
	if code != 0 {
		s.writeResult(id, textResult(true, fmt.Sprintf("%s exited %d, nothing captured", a.Command[0], code)))
		return
	}
	value := strings.TrimSuffix(stdout.String(), "\n")
	value = strings.TrimSuffix(value, "\r")

	// vaultMu (server.go) serializes this whole Open -> mutate -> Save
	// cycle against any other concurrent write tool call (CLA-76). The
	// Vault is re-opened here, under the lock, rather than reusing precheck
	// above, so this always mutates the current on-disk state — including
	// one just written by another capture call that held the lock first —
	// and never overwrites it with a snapshot that predates that write.
	s.vaultMu.Lock()
	defer s.vaultMu.Unlock()
	v, err := s.keyCache.OpenVault() // CLA-77: reuse this server's cached key
	if err != nil {
		s.writeResult(id, textResult(true, err.Error()))
		return
	}
	// Re-checked here, not just above in precheck: argv may have run for a
	// while, and another capture call may have taken this same Handle while
	// it did.
	if _, err := v.Get(a.Handle); err == nil {
		s.writeResult(id, textResult(true, fmt.Sprintf("handle %s already exists", a.Handle)))
		return
	}
	entry, err := v.Add(a.Handle, value, vault.AddOptions{})
	if err != nil {
		s.writeResult(id, textResult(true, err.Error()))
		return
	}
	if err := v.Save(); err != nil {
		s.writeResult(id, textResult(true, err.Error()))
		return
	}
	s.writeResult(id, jsonResult(map[string]any{"handle": entry.Handle}))
}
