package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
