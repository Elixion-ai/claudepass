package e2e

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// childEnv runs the helper under cpass run and returns what it saw in its
// environment, read from a file so nothing goes through stdout.
func childEnv(t *testing.T, ve *vaultEnv, extra []string, args ...string) (map[string]string, result) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "env.txt")
	full := append([]string{"run"}, args...)
	full = append(full, "--", helperBin)
	r := ve.runEnv(append([]string{"HELPER_OUT=" + out}, extra...), nil, full...)
	env := map[string]string{}
	if b, err := os.ReadFile(out); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				env[k] = v
			}
		}
	}
	return env, r
}

func TestRunInjectsDefaultBinding(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", secret)
	env, r := childEnv(t, ve, nil, "--with", "stripe/live")
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	if env["STRIPE_LIVE"] != secret {
		t.Fatalf("child did not receive value under STRIPE_LIVE: %v", env)
	}
	if strings.Contains(r.stdout+r.stderr, secret) {
		t.Fatalf("value leaked to output: %s", r)
	}
}

func TestRunBindingOverride(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", secret)
	env, r := childEnv(t, ve, nil, "--with", "stripe/live:STRIPE_KEY")
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	if env["STRIPE_KEY"] != secret {
		t.Fatalf("override not applied: %v", env)
	}
	if _, ok := env["STRIPE_LIVE"]; ok {
		t.Fatalf("default Binding should not also be set: %v", env)
	}
}

func TestRunMultipleHandlesAndInheritedEnv(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one")
	ve.add("a/two", "value-number-two")
	env, r := childEnv(t, ve, []string{"UNRELATED=keep-me"}, "--with", "a/one", "--with", "a/two")
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	if env["A_ONE"] != "value-number-one" || env["A_TWO"] != "value-number-two" || env["UNRELATED"] != "keep-me" {
		t.Fatalf("env: %v", env)
	}
}

func TestRunPassesExitCodeThrough(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one")
	for _, want := range []string{"0", "3", "42"} {
		_, r := childEnv(t, ve, []string{"HELPER_EXIT=" + want}, "--with", "a/one")
		if got := itoa(r.code); got != want {
			t.Fatalf("exit %s: got %s (%s)", want, got, r)
		}
	}
}

func TestRunReportsSignalDeath(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one")
	_, r := childEnv(t, ve, []string{"HELPER_KILL=9"}, "--with", "a/one")
	if r.code != 137 {
		t.Fatalf("want 137 for SIGKILL, got %s", r)
	}
}

func TestRunPassesStdinAndStdout(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one")
	r := ve.runEnv([]string{"CPASS_TEST_STDIN=0"}, []byte("hello from stdin\n"), "run", "--", "cat")
	if r.code != 0 || r.stdout != "hello from stdin\n" {
		t.Fatalf("stdin/stdout passthrough: %s", r)
	}
	r = ve.runEnv([]string{"HELPER_STDERR=to-stderr"}, nil, "run", "--", helperBin)
	if !strings.Contains(r.stderr, "to-stderr") {
		t.Fatalf("stderr passthrough: %s", r)
	}
}

func TestRunMissingHandleNamesOnlyTheHandle(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one")
	_, r := childEnv(t, ve, nil, "--with", "a/one", "--with", "nope/none")
	if r.code == 0 || !strings.Contains(r.stderr, "no such handle: nope/none") {
		t.Fatalf("missing handle: %s", r)
	}
	if strings.Contains(r.stderr, "value-number-one") {
		t.Fatalf("leaked another value in the error: %s", r)
	}
}

func TestRunLockedFailsFast(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one")
	ve.key = ""
	_, r := childEnv(t, ve, nil, "--with", "a/one")
	if r.code == 0 || !strings.Contains(r.stderr, "locked") || !strings.Contains(r.stderr, "cpass unlock") {
		t.Fatalf("locked: %s", r)
	}
}

func TestRunWithoutCommandIsUsageError(t *testing.T) {
	ve := newVault(t)
	r := ve.run(nil, "run", "--with", "a/one")
	if r.code != 2 || !strings.Contains(r.stderr, "usage") {
		t.Fatalf("usage: %s", r)
	}
}

func TestRunUnknownProgram(t *testing.T) {
	ve := newVault(t)
	r := ve.run(nil, "run", "--", "/definitely/not/here")
	if r.code != 127 {
		t.Fatalf("want 127: %s", r)
	}
}

// TestRunStripsCpassKeyFromChild is the regression test for CLA-54:
// os.Environ() (which carries CPASS_KEY whenever it's how this cpass
// process itself unlocked the Vault, the documented unattended-CI way to
// run it) used to be copied into the child unfiltered. Any child that
// echoes its own environment -- a crash trace, a debug flag, a compromised
// dependency -- handed over the raw Vault master key, not just one Handle.
// Runs with zero --with flags too: the strip must not depend on any Handle
// actually being resolved. The other CPASS_* mode selectors (CPASS_HOME
// above all -- see the CPASS_HOME assertion) must still reach the child, or
// a nested `cpass run` inside a wrapped script would break.
func TestRunStripsCpassKeyFromChild(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one")
	for _, args := range [][]string{nil, {"--with", "a/one"}} {
		env, r := childEnv(t, ve, nil, args...)
		if r.code != 0 {
			t.Fatalf("run %v: %s", args, r)
		}
		if v, ok := env["CPASS_KEY"]; ok && v != "" {
			t.Fatalf("child saw CPASS_KEY=%q with args %v: %v", v, args, env)
		}
		if env["CPASS_HOME"] != ve.home {
			t.Fatalf("CPASS_HOME is a mode selector, not a Secret, and must still reach the child (args %v): %v", args, env)
		}
		if env["PATH"] == "" {
			t.Fatalf("ordinary variables like PATH must still be inherited (args %v): %v", args, env)
		}
	}
}

// TestRunStreamsWithoutBufferingDelay is the e2e regression for PRD story
// #18 (docs/PRD.md): a long-running command's first line must reach the
// Agent well before the command itself exits, not only once the pipe
// closes and the internal Redactor-writer unit tests (idleFlush, Close)
// happen to agree. It reads the live pipe with a short per-read deadline,
// not a fixed sleep, as the actual assertion.
func TestRunStreamsWithoutBufferingDelay(t *testing.T) {
	ve := newVault(t)
	cmd := exec.Command(cpassBin, "run", "--", helperBin)
	cmd.Env = append(append(baseEnv(), "CPASS_HOME="+ve.home, "CPASS_KEY="+ve.key), "HELPER_STREAM_SLEEP_MS=2000")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	lines := make(chan string, 2)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	deadline := time.Second
	if raceEnabled {
		deadline = 1500 * time.Millisecond
	}
	select {
	case line, ok := <-lines:
		if !ok || line != "stream-line-1" {
			t.Fatalf("first line: got %q ok=%v", line, ok)
		}
	case <-time.After(deadline):
		_ = cmd.Process.Kill()
		t.Fatalf("first line did not arrive within %v; output is being buffered until the child exits", deadline)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("cpass run: %v", err)
	}
}

// TestRunBackgroundedForwardsSIGINT is the regression test for CLA-71:
// forwardSignals used to call signal.Notify only after cmd.Start(), so a
// `cpass run -- cmd &` launched as an async shell job with no job control
// (any plain `&`, a CI step, a Makefile target, nohup) forked its child
// while cpass's own SIGINT disposition was still SIG_IGN, the POSIX
// default such a job inherits. The forked child inherited SIG_IGN too and,
// because an ignored signal survives exec(), stayed permanently deaf to
// SIGINT no matter how promptly cpass forwarded it afterward. Launched via
// a raw `sh -c '... &'`, not the test harness's own spawner (exec.Command
// never reproduces this inherited disposition), this is the actual repro.
func TestRunBackgroundedForwardsSIGINT(t *testing.T) {
	ve := newVault(t)
	// The backgrounded job's own stdout/stderr are redirected to /dev/null,
	// not left pointing at the pipe launch.Output() reads: fork inherits
	// file descriptors across `&`, so if cpass (and the sleep it wraps) kept
	// holding that pipe's write end open, Output() would block waiting for
	// EOF until the background job itself exited -- up to the full 30s --
	// and never return the pid in time to test anything.
	script := fmt.Sprintf("%s run -- sleep 30 >/dev/null 2>&1 & echo $!", cpassBin)
	launch := exec.Command("sh", "-c", script)
	launch.Env = append(baseEnv(), "CPASS_HOME="+ve.home, "CPASS_KEY="+ve.key)
	out, err := launch.Output()
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		t.Fatalf("parse backgrounded cpass pid from %q: %v", out, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) }) // best-effort if the assertion below fails first

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = syscall.Kill(pid, syscall.SIGINT)
		if syscall.Kill(pid, 0) != nil {
			return // the backgrounded cpass (and the `sleep` it wraps) is gone
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("cpass pid %d (wrapping `sleep 30` in the background) still alive after repeated SIGINT for ~2s", pid)
}
