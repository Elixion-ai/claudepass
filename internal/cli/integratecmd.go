package cli

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Elixion-ai/claudepass/internal/integrate"
)

func init() {
	register(command{"integrate", "set up (or --remove) an Agent integration: integrate codex|claude|mcp [--path] | --print", cmdIntegrate})
	registerIntegration("codex", integrateCodex)
}

// integrationTarget writes (or would write) the Agent instructions for one
// integration. codex is registered by init() in this file, claude by
// integrate_claude.go, mcp by integrate_mcp.go. Each target lives in its
// own file.
type integrationTarget func(e *env, args []string) int

var integrationTargets = map[string]integrationTarget{}

// registerIntegration adds a `cpass integrate <name>` subcommand.
func registerIntegration(name string, fn integrationTarget) { integrationTargets[name] = fn }

func cmdIntegrate(e *env) int {
	if len(e.args) == 0 {
		return integrateUsage(e)
	}
	if isHelpFlag(e.args[0]) {
		fprintln(e.stdout, integrateUsageText())
		return ExitOK
	}
	if e.args[0] == "--print" {
		if len(e.args) != 1 {
			return e.fail(ExitUsage, "usage: cpass integrate --print")
		}
		fprint(e.stdout, integrate.Snippet)
		return ExitOK
	}
	target, rest := e.args[0], e.args[1:]
	fn, ok := integrationTargets[target]
	if !ok {
		return e.fail(ExitUsage, "unknown integrate target %q (%s)", target, strings.Join(targetNames(), ", "))
	}
	return fn(e, rest)
}

func integrateUsageText() string {
	return "usage: cpass integrate <" + strings.Join(targetNames(), "|") + "> [flags] | --print"
}

func integrateUsage(e *env) int {
	return e.fail(ExitUsage, "%s", integrateUsageText())
}

func targetNames() []string {
	names := make([]string, 0, len(integrationTargets))
	for n := range integrationTargets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// integrateCodex implements `cpass integrate codex [--path FILE] [--remove]`:
// write or replace the delimited ClaudePass section in a Codex AGENTS.md
// file, preserving everything else in it. Idempotent. --remove is the
// inverse: it strips that same delimited section back out (via
// integrate.RemoveSection), deleting the file entirely if the section was
// all it contained, and is itself idempotent and a safe no-op when nothing
// was ever installed.
func integrateCodex(e *env, args []string) int {
	fs := flag.NewFlagSet("integrate codex", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("path", "AGENTS.md", "path to the Codex instructions file")
	remove := fs.Bool("remove", false, "remove the ClaudePass section this command wrote (or the whole file if nothing else remains)")
	if err := fs.Parse(args); err != nil {
		return e.usageErr(err, "cpass integrate codex [--path FILE] [--remove]")
	}
	if fs.NArg() != 0 {
		return e.fail(ExitUsage, "usage: cpass integrate codex [--path FILE] [--remove]")
	}

	existing, err := os.ReadFile(*path)
	fileExisted := err == nil
	if err != nil && !os.IsNotExist(err) {
		return e.failErr(err)
	}

	if *remove {
		if !fileExisted {
			fprintf(e.stdout, "%s does not exist, nothing to remove\n", *path)
			return ExitOK
		}
		updated, found := integrate.RemoveSection(string(existing))
		if !found {
			fprintf(e.stdout, "%s has no ClaudePass section, nothing to remove\n", *path)
			return ExitOK
		}
		if updated == "" {
			if err := os.Remove(*path); err != nil {
				return e.failErr(err)
			}
			fprintf(e.stdout, "removed %s\n", *path)
			return ExitOK
		}
		if err := os.WriteFile(*path, []byte(updated), 0o644); err != nil {
			return e.failErr(err)
		}
		fprintf(e.stdout, "removed the ClaudePass section from %s\n", *path)
		return ExitOK
	}

	updated, changed := integrate.Apply(string(existing))
	if !changed {
		fprintf(e.stdout, "%s already up to date\n", *path)
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
		fprintf(e.stdout, "updated %s\n", *path)
	} else {
		fprintf(e.stdout, "created %s\n", *path)
	}
	return ExitOK
}
