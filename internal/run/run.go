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

	"claudepass/internal/broker"
	"claudepass/internal/policy"
	"claudepass/internal/redact"
	"claudepass/internal/vault"
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
}

// ErrNoCommand is returned when Argv is empty.
var ErrNoCommand = errors.New("no command given after --")

// Run resolves the Spec's Handles, injects them, runs the command, and
// returns its exit code. A child killed by a signal yields 128+signal.
func Run(spec Spec) (int, error) {
	if len(spec.Argv) == 0 {
		return 2, ErrNoCommand
	}
	secrets, err := broker.Resolve(spec.Refs)
	if err != nil {
		return 1, err
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
			fmt.Fprintf(spec.Warn, "cpass: %s is Exposed, rotate it\n", s.Handle)
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
		stdout = redact.NewWriter(spec.Stdout, "stdout", patterns, rlog.Record)
	}
	stderr := redact.NewWriter(spec.Stderr, "stderr", patterns, rlog.Record)

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
	stdout.Close()
	stderr.Close()
	if spec.Warn != nil {
		counts := rlog.Counts()
		handles := make([]string, 0, len(counts))
		for h := range counts {
			handles = append(handles, h)
		}
		sort.Strings(handles)
		for _, h := range handles {
			fmt.Fprintf(spec.Warn, "cpass: redacted %s from output (%d×); the Agent must use the value, not print it\n", h, counts[h])
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
