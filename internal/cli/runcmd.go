package cli

import (
	"errors"
	"flag"
	"io"
	"strings"

	"claudepass/internal/broker"
	"claudepass/internal/manifest"
	"claudepass/internal/policy"
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
	fs.SetOutput(io.Discard)
	var with multiFlag
	fs.Var(&with, "with", "Handle to inject, optionally with a Binding override (handle:VAR); repeatable")
	unsafe := fs.Bool("unsafe-allow", false, "skip Command Policy (humans only; refused without a terminal)")
	if err := fs.Parse(e.args); err != nil {
		return e.usageErr(err, "cpass run [--with handle[:VAR]]... [--unsafe-allow] -- <command> [args]")
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return e.fail(ExitUsage, "usage: cpass run [--with handle[:VAR]]... -- <command> [args]")
	}
	var refs []broker.Ref
	if p, err := manifest.Find("."); err == nil {
		m, err := manifest.Load(p)
		if err != nil {
			return e.failErr(err)
		}
		for _, en := range m.Entries {
			refs = append(refs, broker.Ref{Handle: en.Handle, Declared: en.Binding})
		}
	} else if !errors.Is(err, manifest.ErrNotFound) {
		return e.failErr(err)
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
	code, err := run.Run(run.Spec{
		Refs: refs, Argv: argv, UnsafeAllow: *unsafe,
		Stdin: e.stdin, Stdout: e.stdout, Stderr: e.stderr, Warn: e.stderr,
		DecorateStdoutMarker: markerDecorator(e.outMode),
		DecorateStderrMarker: markerDecorator(e.errMode),
		FormatExposed:        e.exposed,
	})
	if err != nil {
		if errors.Is(err, run.ErrNoCommand) {
			return e.fail(ExitUsage, "%v", err)
		}
		var ref *policy.Refusal
		if errors.As(err, &ref) {
			return e.refuse(ref.Rule, ref.Advice)
		}
		return e.fail(code, "%v", err)
	}
	return code
}
