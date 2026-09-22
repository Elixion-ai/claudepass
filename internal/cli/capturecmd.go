package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/policy"
	"github.com/Elixion-ai/claudepass/internal/run"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

func init() {
	register(command{"capture", "store a command's stdout as a new Secret: cpass capture handle -- cmd", cmdCapture})
}

const captureUsage = "usage: cpass capture <handle> [--with handle[:VAR]]... [--binding NAME] [--file] [--unsafe-allow] -- <command> [args]"

func cmdCapture(e *env) int {
	head, argv, hasDoubleDash := splitDoubleDash(e.args)

	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var with multiFlag
	fs.Var(&with, "with", "another Handle to inject into the command, optionally with a Binding override (handle:VAR); repeatable")
	binding := fs.String("binding", "", "environment variable name for the captured Secret's default Binding")
	file := fs.Bool("file", false, "bind the captured Secret as a temp file whose path is placed in the variable")
	unsafe := fs.Bool("unsafe-allow", false, "skip Command Policy (humans only; refused without a terminal)")
	pos, err := parseInterspersed(fs, head)
	if err != nil {
		return e.usageErr(err, "cpass capture <handle> [--with handle[:VAR]]... [--binding NAME] [--file] [--unsafe-allow] -- <command> [args]")
	}
	if !hasDoubleDash || len(pos) != 1 || len(argv) == 0 {
		return e.fail(ExitUsage, captureUsage)
	}
	handle := pos[0]
	if err := vault.ValidateHandle(handle); err != nil {
		return e.failErr(err)
	}

	// Fail fast, before running (possibly slow, possibly untrusted)
	// argv, and reject the common case of an already-used Handle without
	// holding the write lock across a child process of arbitrary duration
	// — see the broker.UpdateVault call below, at the end, for the check
	// that actually has to be race-free with another writer.
	precheck, code := openVault(e)
	if code != ExitOK {
		return code
	}
	_, getErr := precheck.Get(handle)
	precheck.Close()
	if getErr == nil {
		return e.fail(ExitError, "handle %s already exists", handle)
	}

	var refs []broker.Ref
	for _, w := range with {
		r, err := broker.ParseRef(w)
		if err != nil {
			return e.failErr(err)
		}
		refs = append(refs, r)
	}

	if *unsafe && !e.humanPresent() {
		return e.refuse("--unsafe-allow needs a terminal", "only a human may skip Command Policy")
	}

	var stdout bytes.Buffer
	exitCode, err := run.Run(run.Spec{
		Refs: refs, Argv: argv, UnsafeAllow: *unsafe, RawStdout: true,
		Stdin: e.stdin, Stdout: &stdout, Stderr: e.stderr, Warn: e.stderr,
		// Stdout is captured raw (RawStdout above) into the new Secret's
		// value, never shown to anyone, so it needs no marker colour;
		// stderr is still a real destination a human may be watching.
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
		return e.failErr(err)
	}
	if exitCode != 0 {
		return e.fail(ExitError, "%s exited %d, nothing captured", argv[0], exitCode)
	}

	value := strings.TrimSuffix(stdout.String(), "\n")
	value = strings.TrimSuffix(value, "\r")

	opts := vault.AddOptions{Binding: vault.Binding{Name: *binding}}
	if *file {
		opts.Binding.Kind = vault.BindFile
	}
	var entry vault.Entry
	code = updateVault(e, func(v *vault.Vault) error {
		// Re-checked here, not just above: argv may have run for a while,
		// and this is the freshly reopened, lock-protected state another
		// writer could have changed in the meantime (CLA-55).
		if _, err := v.Get(handle); err == nil {
			return fmt.Errorf("handle %s already exists", handle)
		}
		var err error
		entry, err = v.Add(handle, value, opts)
		return err
	})
	if code != ExitOK {
		return code
	}
	fprintln(e.stdout, entry.Handle)
	return ExitOK
}

// splitDoubleDash finds the first literal "--" argument and splits args
// around it, the way `cpass capture <handle> [flags] -- <command>` needs:
// flags before, an arbitrary (unparsed) command after.
func splitDoubleDash(args []string) (head, rest []string, found bool) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}
