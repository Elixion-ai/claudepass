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
	env := os.Environ()
	var patterns []redact.Pattern
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
		return 127, fmt.Errorf("cannot start %s: %w", spec.Argv[0], err)
	}
	stop := forwardSignals(cmd.Process)
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
