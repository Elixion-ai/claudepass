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
	// Resolver, when set, resolves Refs in place of the package-level
	// broker.Resolve — cpass mcp passes a broker.KeyCache's own Resolve
	// method here so run_with_secrets reuses that server process's cached
	// unlock key (CLA-77) instead of paying OpenVault()'s cost on every
	// call. Left nil (every CLI command), Refs resolve through the always-
	// fresh broker.Resolve, unchanged.
	Resolver func(refs []broker.Ref) ([]broker.Resolved, []string, error)
	// Cancel, when set and then closed, kills the child (see
	// killProcessGroup) as soon as possible instead of waiting on it to
	// exit on its own. cpass mcp sets this per call from a request's own
	// notifications/cancelled (see internal/mcp) so a client can actually
	// interrupt a run_with_secrets/capture call it no longer wants; the CLI
	// never sets it; forwardSignals' relay of an OS SIGINT/SIGTERM/SIGHUP to
	// the child is unrelated and unaffected either way.
	Cancel <-chan struct{}
}

// ErrNoCommand is returned when Argv is empty.
var ErrNoCommand = errors.New("no command given after --")

// Run resolves the Spec's Handles, injects them, runs the command, and
// returns its exit code. A child killed by a signal yields 128+signal — a
// child Spec.Cancel killed included, since that is exactly what it does.
func Run(spec Spec) (int, error) {
	if len(spec.Argv) == 0 {
		return 2, ErrNoCommand
	}
	resolve := broker.Resolve
	if spec.Resolver != nil {
		resolve = spec.Resolver
	}
	secrets, skipped, err := resolve(spec.Refs)
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
		// spec.Dir is the directory the command is about to actually run
		// in (cmd.Dir below) — passed through as Cwd so a relative reader
		// argument resolves against the same directory the child itself
		// will see, not this long-lived process's own (the MCP server's
		// case; cpass run leaves spec.Dir empty, since for it the two
		// already coincide — see policy.Input.Cwd).
		in := policy.Input{Argv: spec.Argv, ProtectedDirs: []string{root}, Cwd: spec.Dir}
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
	// but whenever it *could have been* the source this invocation (or a
	// caller wrapping it) unlocked the Vault with, register it as a redact
	// Pattern too, as defense in depth against some *other* route a child
	// might still echo it back through.
	//
	// This used to be gated on len(spec.Refs) > 0, as a proxy for "this
	// call's own broker.Resolve opened the Vault with CPASS_KEY" — correct
	// for `cpass run` (Resolve never opens the Vault when Refs is empty),
	// but wrong for `cpass capture` and the MCP `capture` tool: both open
	// the Vault themselves via their own broker.OpenVault() call, before
	// Run is ever invoked, to check the target Handle doesn't already
	// exist, independent of Refs — and the MCP capture tool has no
	// Refs-equivalent at all, so it could never satisfy that guard. CPASS_KEY
	// genuinely was the unlock source there too whenever it is set, since
	// broker.UnlockKey always tries it first, ahead of the Keychain and the
	// Broker socket.
	//
	// So the guard is now simply "CPASS_KEY is set and this isn't CI mode"
	// (CI mode never opens the Vault, from any caller): resolveFromEnv
	// never touches the Vault, and OpenVault is the only remaining caller
	// of UnlockKey, so whenever CPASS_KEY is set outside CI mode, either
	// this call's own Resolve or a caller's own pre-existing OpenVault call
	// used it to unlock. A run that touches the Vault via neither (e.g.
	// `cpass run` with no --with at all) still passes this check and
	// registers the pattern for nothing — harmless: an unused pattern only
	// matches if the child happens to print that exact literal, the same
	// preexisting risk any registered pattern already carries.
	if key := os.Getenv(broker.EnvKey); key != "" && !broker.CIMode() {
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
	// rlog opens redactions.log lazily, on its first event; Close (safe to
	// call even when nothing was ever redacted) releases it on every exit
	// path from here on, so this one invocation's log file handle never
	// outlives the invocation.
	defer func() { _ = rlog.Close() }()
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
	// Registered before Start(), not after: signal.Notify changes cpass's
	// own SIGINT/SIGTERM/SIGHUP disposition immediately, and it is cpass's
	// disposition *at fork time* that the child inherits. A `cpass run --
	// cmd &` launched by an async shell job (no job control — any plain
	// `&`, a CI step, a Makefile target, nohup) starts with SIGINT already
	// SIG_IGN; forked before this call, the child would inherit SIG_IGN too
	// and, since an ignored signal survives exec(), stay permanently deaf
	// to every SIGINT cpass forwards to it afterward, however promptly.
	// Registering first flips cpass's own disposition to "caught" before
	// the fork, so the child inherits that instead and gets it reset to
	// SIG_DFL across its own exec() — normal, killable-by-default. sigCh is
	// buffered so a signal landing in the narrow window between here and
	// forwardSignals' goroutine starting (which needs cmd.Process, so it
	// can only start once Start() returns) is queued, not lost.
	sigCh := notifySignals()
	if spec.Cancel != nil {
		// Isolate the child (and anything it forks, e.g. a wrapping shell's
		// own children) into its own process group so a cancellation can
		// kill the whole thing at once — see killProcessGroup. The CLI
		// never sets Cancel, so an interactive `cpass run`'s child keeps
		// sharing cpass's own process group, and so the terminal's own
		// Ctrl-C delivery, exactly as before; this only changes process-
		// group membership for a call cpass mcp made cancellable.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if err := cmd.Start(); err != nil {
		signal.Stop(sigCh)
		return 127, fmt.Errorf("cannot start %s: %w", spec.Argv[0], err)
	}
	stop := forwardSignals(sigCh, cmd.Process)
	cancelDone := make(chan struct{})
	if spec.Cancel != nil {
		go func() {
			select {
			case <-spec.Cancel:
				killProcessGroup(cmd.Process)
			case <-cancelDone:
			}
		}()
	}
	err = cmd.Wait()
	stop()
	close(cancelDone)
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

// notifySignals registers cpass's own SIGINT/SIGTERM/SIGHUP disposition.
// Callers must invoke this before cmd.Start() — see the ordering comment at
// the call site — and pass the returned channel to forwardSignals once
// cmd.Process exists.
func notifySignals() chan os.Signal {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	return ch
}

// forwardSignals relays every signal arriving on ch (already registered by
// notifySignals, before the child was forked) to the child so Ctrl-C
// behaves as if cpass were not in the way.
func forwardSignals(ch chan os.Signal, p *os.Process) func() {
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

// killProcessGroup terminates p unconditionally: SIGKILL to its whole
// process group when it has one of its own (Spec.Cancel's caller sets
// Setpgid above precisely so this reaches a wrapping shell's own children
// too, e.g. "sh -c sleep 30" — a single p.Kill() would leave sleep
// orphaned and running), falling back to killing p alone otherwise. A
// cancellation has already told the child it is no longer wanted; there is
// no one left to negotiate a graceful SIGTERM shutdown with.
func killProcessGroup(p *os.Process) {
	if pgid, err := syscall.Getpgid(p.Pid); err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL) // best-effort: p may have already exited
		return
	}
	_ = p.Kill() // best-effort, same reason
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
