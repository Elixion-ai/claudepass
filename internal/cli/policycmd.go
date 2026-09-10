package cli

import (
	"encoding/json"
	"flag"
	"io"
	"strings"

	"claudepass/internal/policy"
)

func init() {
	register(command{"policy", "evaluate Command Policy: --hook reads a Claude Code PreToolUse Bash event on stdin", cmdPolicy})
}

// preToolUseInput is the subset of Claude Code's PreToolUse hook JSON this
// command reads from stdin. Real hook invocations carry more fields
// (session_id, transcript_path, cwd, permission_mode, tool_use_id, ...) and
// tool_input carries more than command for some tools; only what --hook
// needs is read here, the rest is ignored.
type preToolUseInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

func cmdPolicy(e *env) int {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	hook := fs.Bool("hook", false, "read a Claude Code PreToolUse Bash event from stdin and apply Command Policy")
	if _, err := parseInterspersed(fs, e.args); err != nil {
		return ExitUsage
	}
	if !*hook {
		return e.fail(ExitUsage, "usage: cpass policy --hook")
	}

	raw, err := io.ReadAll(e.stdin)
	if err != nil {
		return e.failErr(err)
	}
	var in preToolUseInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return e.fail(ExitUsage, "invalid hook JSON on stdin: %v", err)
	}
	// The plugin's own hooks.json matcher already limits PreToolUse to
	// Bash, but a stray or hand-fed event should pass through rather than
	// be judged as a command it never was.
	if in.ToolName != "" && in.ToolName != "Bash" {
		return ExitOK
	}
	if strings.TrimSpace(in.ToolInput.Command) == "" {
		return ExitOK
	}

	if err := policy.EvaluateHook(in.ToolInput.Command); err != nil {
		// Claude Code's PreToolUse hook protocol: exit 2 blocks the tool
		// call and shows this stderr text to the human.
		fprintf(e.stderr, "cpass: %v\n", err)
		return ExitUsage
	}
	return ExitOK
}
