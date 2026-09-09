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

	"claudepass/internal/broker"
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
	env := os.Environ()
	for _, s := range secrets {
		if s.Binding.Kind != vault.BindEnv {
			return 1, fmt.Errorf("%s has a file Binding, which cpass run does not support yet", s.Handle)
		}
		env = setEnv(env, s.Binding.Name, s.Value)
		if s.Exposed && spec.Warn != nil {
			fmt.Fprintf(spec.Warn, "cpass: %s is Exposed, rotate it\n", s.Handle)
		}
	}
	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...)
	cmd.Env = env
	cmd.Dir = spec.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Stdin, spec.Stdout, spec.Stderr
	if err := cmd.Start(); err != nil {
		return 127, fmt.Errorf("cannot start %s: %w", spec.Argv[0], err)
	}
	stop := forwardSignals(cmd.Process)
	defer stop()
	err = cmd.Wait()
	return exitCode(err), nil
}

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
