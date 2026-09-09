package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"claudepass/internal/integrate"
)

func init() {
	register(command{"integrate", "write Agent instructions into a project: integrate codex [--path] | --print", cmdIntegrate})
	registerIntegration("codex", integrateCodex)
}

// integrationTarget writes (or would write) the Agent instructions for one
// integration. Registered by init() in this file and, later, by CLA-11
// (claude) and CLA-13 (mcp), so each target lives in its own file.
type integrationTarget func(e *env, args []string) int

var integrationTargets = map[string]integrationTarget{}

// registerIntegration adds a `cpass integrate <name>` subcommand.
func registerIntegration(name string, fn integrationTarget) { integrationTargets[name] = fn }

func cmdIntegrate(e *env) int {
	if len(e.args) == 0 {
		return integrateUsage(e)
	}
	if e.args[0] == "--print" {
		if len(e.args) != 1 {
			return e.fail(ExitUsage, "usage: cpass integrate --print")
		}
		fmt.Fprint(e.stdout, integrate.Snippet)
		return ExitOK
	}
	target, rest := e.args[0], e.args[1:]
	fn, ok := integrationTargets[target]
	if !ok {
		return e.fail(ExitUsage, "unknown integrate target %q (%s)", target, strings.Join(targetNames(), ", "))
	}
	return fn(e, rest)
}

func integrateUsage(e *env) int {
	return e.fail(ExitUsage, "usage: cpass integrate <%s> [flags] | --print", strings.Join(targetNames(), "|"))
}

func targetNames() []string {
	names := make([]string, 0, len(integrationTargets))
	for n := range integrationTargets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// integrateCodex implements `cpass integrate codex [--path FILE]`: write or
// replace the delimited ClaudePass section in a Codex AGENTS.md file,
// preserving everything else in it. Idempotent.
func integrateCodex(e *env, args []string) int {
	fs := flag.NewFlagSet("integrate codex", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	path := fs.String("path", "AGENTS.md", "path to the Codex instructions file")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 0 {
		return e.fail(ExitUsage, "usage: cpass integrate codex [--path FILE]")
	}

	existing, err := os.ReadFile(*path)
	fileExisted := err == nil
	if err != nil && !os.IsNotExist(err) {
		return e.failErr(err)
	}

	updated, changed := integrate.Apply(string(existing))
	if !changed {
		fmt.Fprintf(e.stdout, "%s already up to date\n", *path)
		return ExitOK
	}
	if dir := filepath.Dir(*path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return e.failErr(err)
		}
	}
	if err := os.WriteFile(*path, []byte(updated), 0o644); err != nil {
		return e.failErr(err)
	}
	if fileExisted {
		fmt.Fprintf(e.stdout, "updated %s\n", *path)
	} else {
		fmt.Fprintf(e.stdout, "created %s\n", *path)
	}
	return ExitOK
}
