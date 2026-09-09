package cli

import (
	"errors"
	"flag"
	"strings"

	"claudepass/internal/broker"
	"claudepass/internal/run"
)

func init() {
	register(command{"run", "run a command with Secrets injected: cpass run --with h[:VAR] -- cmd", cmdRun})
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func cmdRun(e *env) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var with multiFlag
	fs.Var(&with, "with", "Handle to inject, optionally with a Binding override (handle:VAR); repeatable")
	if err := fs.Parse(e.args); err != nil {
		return ExitUsage
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return e.fail(ExitUsage, "usage: cpass run [--with handle[:VAR]]... -- <command> [args]")
	}
	refs := make([]broker.Ref, 0, len(with))
	for _, w := range with {
		r, err := broker.ParseRef(w)
		if err != nil {
			return e.failErr(err)
		}
		refs = append(refs, r)
	}
	code, err := run.Run(run.Spec{
		Refs: refs, Argv: argv,
		Stdin: e.stdin, Stdout: e.stdout, Stderr: e.stderr, Warn: e.stderr,
	})
	if err != nil {
		if errors.Is(err, run.ErrNoCommand) {
			return e.fail(ExitUsage, "%v", err)
		}
		return e.fail(code, "%v", err)
	}
	return code
}
