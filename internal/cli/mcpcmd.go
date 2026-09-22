package cli

import (
	"flag"
	"io"

	"github.com/Elixion-ai/claudepass/internal/mcp"
)

func init() {
	register(command{"mcp", "speak MCP over stdio: list_handles, run_with_secrets, capture", cmdMCP})
}

func cmdMCP(e *env) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass mcp")
	}
	if fs.NArg() != 0 {
		return e.fail(ExitUsage, "usage: cpass mcp")
	}
	// effectiveVersion, not the raw Version, so a `go install` build's
	// initialize response names the same version `cpass version` prints
	// instead of always falling back to "dev" (CLA-98 item 6).
	if err := mcp.Serve(e.stdin, e.stdout, e.stderr, effectiveVersion()); err != nil {
		return e.failErr(err)
	}
	return ExitOK
}
