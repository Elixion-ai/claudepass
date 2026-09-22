package cli

import (
	"errors"
	"flag"
	"io"
	"strings"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/manifest"
	"github.com/Elixion-ai/claudepass/internal/policy"
	"github.com/Elixion-ai/claudepass/internal/run"
)

func init() {
	register(command{"run", "run a command with Secrets injected: cpass run --with h[:VAR] -- cmd", cmdRun})
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func cmdRun(e *env) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var with multiFlag
	fs.Var(&with, "with", "Handle to inject, optionally with a Binding override (handle:VAR); repeatable")
	noGlobal := fs.Bool("no-global", false, "skip the Global Manifest's Handles for this run")
	unsafe := fs.Bool("unsafe-allow", false, "skip Command Policy (humans only; refused without a terminal)")
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass run [--with handle[:VAR]]... [--no-global] [--unsafe-allow] -- <command> [args]")
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return e.fail(ExitUsage, "usage: cpass run [--with handle[:VAR]]... [--no-global] -- <command> [args]")
	}
	refs, notices, err := manifest.Refs(".", !*noGlobal)
	if err != nil {
		return e.failErr(err)
	}
	for _, n := range notices {
		fprintln(e.stderr, n)
	}
	for _, w := range with {
		r, err := broker.ParseRef(w)
		if err != nil {
			return e.failErr(err)
		}
		replaced := false
		for i := range refs {
			if refs[i].Handle == r.Handle {
				refs[i].Override = r.Override
				// Naming a Handle on the command line makes it explicitly
				// requested, so it stops being ambient: it must hard-fail
				// when it cannot be resolved, not be skipped as a drifted
				// Global declaration. Mirrors replaceOrAppend in
				// internal/manifest/refs.go, which clears the same mark when
				// a project Manifest supersedes a Global entry.
				refs[i].FromGlobal = false
				replaced = true
			}
		}
		if !replaced {
			refs = append(refs, r)
		}
	}

	if *unsafe && !e.humanPresent() {
		return e.refuse("--unsafe-allow needs a terminal", "only a human may skip Command Policy")
	}
	code, runErr := run.Run(run.Spec{
		Refs: refs, Argv: argv, UnsafeAllow: *unsafe,
		Stdin: e.stdin, Stdout: e.stdout, Stderr: e.stderr, Warn: e.stderr,
		DecorateStdoutMarker: markerDecorator(e.outMode),
		DecorateStderrMarker: markerDecorator(e.errMode),
		FormatExposed:        e.exposed,
	})
	if runErr != nil {
		if errors.Is(runErr, run.ErrNoCommand) {
			return e.fail(ExitUsage, "%v", runErr)
		}
		var ref *policy.Refusal
		if errors.As(runErr, &ref) {
			return e.refuse(ref.Rule, ref.Advice)
		}
		return e.fail(code, "%v", runErr)
	}
	return code
}
