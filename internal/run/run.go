// Package run executes a command with Secrets injected by the Broker. It is
// the single path every surface (CLI, MCP) uses, so behaviour is identical.
package run

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"path/filepath"
	"sort"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/policy"
	"github.com/Elixion-ai/claudepass/internal/redact"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

// Spec describes one wrapped command.
type Spec struct {
	Refs   []broker.Ref
	Argv   []string
	Dir    string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Warn receives one-line notices for the human (e.g. Exposed reminders).
	Warn io.Writer
	// UnsafeAllow skips Command Policy. The CLI only sets it for a human.
	UnsafeAllow bool
	// RawStdout writes the child's stdout to Stdout unredacted, bypassing the
	// Redactor entirely. cpass capture sets this: stdout is stored directly
	// as a new Secret rather than shown to an Agent, so there is nothing to
	// redact it from and redacting it would corrupt the captured value.
	// Stderr is still redacted and Command Policy still applies.
	RawStdout bool
	// DecorateStdoutMarker and DecorateStderrMarker, when set, wrap each
	// [REDACTED:...] marker written to the corresponding stream — the CLI
	// sets these to colour the marker red when that specific stream is a
	// TTY with colour on (docs/CLI-STYLE.md's Colour section), never
	// otherwise. Left nil, the marker is exactly Marker(handle), unchanged.
	DecorateStdoutMarker func(handle string, marker []byte) []byte
	DecorateStderrMarker func(handle string, marker []byte) []byte
	// FormatExposed, when set, renders the Exposed-reminder line for one
	// Secret (docs/CLI-STYLE.md: "cpass: <handle> is Exposed since <date>,
	// rotate it") — the CLI sets this to internal/cli's own env.exposed so
	// the reminder is coloured through Warn's stream the same way every
	// other diagnostic in internal/cli/cli.go is (ember handle, red
	// "Exposed", dim date), instead of Run hand-rolling a second, always-
	// plain copy of that grammar. Left nil (as internal/mcp's callers leave
	// it, since an MCP client is never a human terminal), the reminder is
	// the same plain "cpass: <handle> is Exposed since <date>, rotate it"
	// wording, unchanged.
	FormatExposed func(handle, since string) string
}

// ErrNoCommand is returned when Argv is empty.
var ErrNoCommand = errors.New("no command given after --")

// Run resolves the Spec's Handles, injects them, runs the command, and
// returns its exit code. A child killed by a signal yields 128+signal.
func Run(spec Spec) (int, error) {
	if len(spec.Argv) == 0 {
		return 2, ErrNoCommand
	}
	secrets, skipped, err := broker.Resolve(spec.Refs)
	if err != nil {
		return 1, err
	}
	for _, line := range skipped {
		if spec.Warn != nil {
			// Best-effort, like every other notice below: a drifted Global
			// Handle is worth saying out loud, but never worth failing over.
			_, _ = fmt.Fprintln(spec.Warn, line)
		}
	}
	root, _ := runRoot()
	if !spec.UnsafeAllow {
		in := policy.Input{Argv: spec.Argv, ProtectedDirs: []string{root}}
		for _, s := range secrets {
			in.Bound = append(in.Bound, policy.Var{Name: s.Binding.Name, Kind: s.Binding.Kind})
		}
		if err := policy.Evaluate(in); err != nil {
			return 3, err
		}
	}
	env := stripSecretEnv(os.Environ())
	var patterns []redact.Pattern
	// CPASS_KEY (the Vault's unlock key, base64) never reaches a child's
	// environment (stripSecretEnv above), however it reached cpass's own —
	// but if it *was* the source this invocation actually unlocked the
	// Vault with (broker.UnlockKey tries it first, ahead of the Keychain
	// and the Broker socket, and only when secrets are being resolved from
	// the Vault at all: CI mode never opens it), register it as a redact
	// Pattern too, as defense in depth against some *other* route a child
	// might still echo it back through. Reaching this point with
	// broker.Resolve having returned no error already confirms it was
	// actually used, not merely present and unrelated.
	if key := os.Getenv(broker.EnvKey); key != "" && len(spec.Refs) > 0 && !broker.CIMode() {
		patterns = append(patterns, redact.Variants(cpassKeyPseudoHandle, key)...)
	}
	var dir *runDir
	defer func() { dir.destroy() }()
	for _, s := range secrets {
		switch s.Binding.Kind {
		case vault.BindFile:
			if dir == nil {
				d, err := newRunDir()
				if err != nil {
					return 1, err
				}
				dir = d
			}
			path, err := dir.add(s.Handle, s.Value)
			if err != nil {
				return 1, err
			}
			env = setEnv(env, s.Binding.Name, path)
		default:
			env = setEnv(env, s.Binding.Name, s.Value)
		}
		patterns = append(patterns, redact.Variants(s.Handle, s.Value)...)
		if s.Exposed && spec.Warn != nil {
			since := "an unknown date"
			if !s.ExposedAt.IsZero() {
				since = s.ExposedAt.Format("2006-01-02")
			}
			line := fmt.Sprintf("cpass: %s is Exposed since %s, rotate it", s.Handle, since)
			if spec.FormatExposed != nil {
				line = spec.FormatExposed(s.Handle, since)
			}
			// Best-effort, like every other human-facing notice cpass prints: a
			// broken Warn stream isn't actionable here and the run proceeds
			// either way.
			_, _ = fmt.Fprintln(spec.Warn, line)
		}
	}
	logPath := ""
	if home, err := broker.Home(); err == nil {
		logPath = filepath.Join(home, "redactions.log")
	}
	rlog := redact.NewLog(logPath, filepath.Base(spec.Argv[0]))
	var stdout io.WriteCloser
	if spec.RawStdout {
		stdout = nopWriteCloser{spec.Stdout}
	} else {
		stdout = redact.NewWriter(spec.Stdout, "stdout", patterns, rlog.Record,
			redact.WithMarkerDecorator(spec.DecorateStdoutMarker))
	}
	stderr := redact.NewWriter(spec.Stderr, "stderr", patterns, rlog.Record,
		redact.WithMarkerDecorator(spec.DecorateStderrMarker))

	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...)
	cmd.Env = env
	cmd.Dir = spec.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Stdin, stdout, stderr
	if err := cmd.Start(); err != nil {
		return 127, fmt.Errorf("cannot start %s: %w", spec.Argv[0], err)
	}
	stop := forwardSignals(cmd.Process)
	err = cmd.Wait()
	stop()
	dir.destroy()
	// Best-effort: the child has already exited, there is nothing left to
	// do with a broken stdout/stderr (e.g. a downstream reader that closed
	// its pipe early) than what happens anyway — cpass returns the child's
	// exit code below, same as if the write had gone through.
	_ = stdout.Close()
	_ = stderr.Close()
	if spec.Warn != nil {
		counts := rlog.Counts()
		handles := make([]string, 0, len(counts))
		for h := range counts {
			handles = append(handles, h)
		}
		sort.Strings(handles)
		for _, h := range handles {
			_, _ = fmt.Fprintf(spec.Warn, "cpass: redacted %s from output (%d×); the Agent must use the value, not print it\n", h, counts[h]) // best-effort, see above
		}
	}
	return exitCode(err), nil
}

// nopWriteCloser adapts an io.Writer to io.WriteCloser with a no-op Close,
// so RawStdout can share the same shutdown path as the redacted writers.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func setEnv(env []string, name, value string) []string {
	prefix := name + "="
	for i, kv := range env {
		if len(kv) >= len(prefix) && kv[:len(prefix)] == prefix {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

// cpassKeyPseudoHandle labels the redact Pattern registered for CPASS_KEY
// itself (see env := stripSecretEnv... above) — not a real Vault Handle, a
// reserved name (the "cpass/" segment no project Handle collides with in
// practice) so [REDACTED:cpass/vault-key] and the redaction log both read
// unambiguously as "the unlock key", not "some Handle named this".
const cpassKeyPseudoHandle = "cpass/vault-key"

// stripSecretEnv removes cpass's own Secret-bearing control variable from a
// copy of os.Environ() before it becomes a child's environment. Only
// CPASS_KEY carries Secret material — the Vault's unlock key, base64 — so
// it alone is stripped, unconditionally, regardless of --with/Refs. Every
// other CPASS_* variable cpass itself reads (CPASS_HOME, CPASS_UNLOCK,
// CPASS_CI, CPASS_KEYCHAIN_SERVICE) is a mode selector carrying no Secret
// value, and is passed through unchanged on purpose: a nested `cpass run`
// inside a wrapped script (a Makefile target, a CI step that itself shells
// out to `cpass`) still resolves CPASS_HOME and still finds the Vault — it
// just cannot use the CPASS_KEY env-unlock path (the one thing that got
// stripped) and instead needs the macOS Keychain or the Linux/CI Broker
// socket, neither of which needs an env key (see docs/SECURITY.md).
func stripSecretEnv(env []string) []string {
	out := env[:0:0] // fresh backing array: os.Environ() is never aliased elsewhere
	for _, kv := range env {
		if strings.HasPrefix(kv, broker.EnvKey+"=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// forwardSignals relays SIGINT and SIGTERM to the child so Ctrl-C behaves
// as if cpass were not in the way.
func forwardSignals(p *os.Process) func() {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-ch:
				_ = p.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	return func() { signal.Stop(ch); close(done) }
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return 1
}
