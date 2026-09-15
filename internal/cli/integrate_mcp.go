package cli

import (
	"flag"
	"io"

	"github.com/Elixion-ai/claudepass/internal/integrate"
)

func init() {
	registerIntegration("mcp", integrateMCP)
}

// integrateMCP implements `cpass integrate mcp`: print the JSON config
// snippet that registers the ClaudePass MCP server (`cpass mcp`) with an
// MCP-aware Agent — Claude Code's `claude mcp add-json`, a `.mcp.json`
// file, or Codex's MCP server config all read this same
// name/command/args shape. Unlike `integrate codex` this never writes a
// file: every client keeps its config somewhere different, so the snippet
// is meant to be pasted.
func integrateMCP(e *env, args []string) int {
	fs := flag.NewFlagSet("integrate mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return e.usageErr(err, "cpass integrate mcp")
	}
	if fs.NArg() != 0 {
		return e.fail(ExitUsage, "usage: cpass integrate mcp")
	}
	fprint(e.stdout, integrate.MCPSnippet)
	return ExitOK
}
