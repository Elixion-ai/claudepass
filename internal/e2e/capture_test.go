package e2e

import (
	"strings"
	"testing"
)

// TestCaptureStoresStdoutAndPrintsHandle is also the "capture needs no
// terminal" test: like every other test in this harness, cpass runs here
// with stdin attached to nothing a human could type into, and this is the
// path an Agent uses.
func TestCaptureStoresStdoutAndPrintsHandle(t *testing.T) {
	ve := newVault(t)
	r := ve.run(nil, "capture", "demo/token", "--", "sh", "-c", "echo tok_abcdef123456")
	if r.code != 0 {
		t.Fatalf("capture: %s", r)
	}
	if strings.TrimSpace(r.stdout) != "demo/token" {
		t.Fatalf("capture's own stdout should be only the Handle: %s", r)
	}
	if strings.Contains(r.stdout, "tok_") {
		t.Fatalf("captured value leaked to capture's own stdout: %s", r)
	}
	env, run := childEnv(t, ve, nil, "--with", "demo/token")
	if run.code != 0 {
		t.Fatalf("run --with demo/token: %s", run)
	}
	if env["DEMO_TOKEN"] != "tok_abcdef123456" {
		t.Fatalf("captured value not what the command echoed: %v", env)
	}
}

func TestCaptureRequiresDoubleDashAndCommand(t *testing.T) {
	ve := newVault(t)
	for _, args := range [][]string{
		{"capture", "demo/token"},
		{"capture", "demo/token", "--"},
	} {
		r := ve.run(nil, args...)
		if r.code != 2 || !strings.Contains(r.stderr, "usage") {
			t.Fatalf("want usage error for %v: %s", args, r)
		}
	}
}

func TestCaptureRejectsExistingHandle(t *testing.T) {
	ve := newVault(t)
	ve.add("demo/token", "already-here-value")
	r := ve.run(nil, "capture", "demo/token", "--", "sh", "-c", "echo tok_abcdef123456")
	if r.code == 0 || !strings.Contains(r.stderr, "demo/token") || !strings.Contains(r.stderr, "already exists") {
		t.Fatalf("want collision refusal: %s", r)
	}
}

func TestCaptureRefusesOnNonZeroExit(t *testing.T) {
	ve := newVault(t)
	r := ve.run(nil, "capture", "demo/token", "--", "sh", "-c", "echo tok_abcdef123456; exit 3")
	if r.code == 0 || !strings.Contains(r.stderr, "exited 3") {
		t.Fatalf("want refusal on nonzero exit: %s", r)
	}
	ls := ve.run(nil, "ls")
	if strings.Contains(ls.stdout, "demo/token") {
		t.Fatalf("should not store on a nonzero exit: %s", ls)
	}
}

// TestCaptureWithInjectsOtherHandles proves --with reaches the wrapped
// command's environment. It uses helperBin directly (not a shell) because
// Command Policy refuses any shell echo/printf that references a bound
// variable regardless of what it's combined with — the same rule cpass run
// already enforces, and out of scope here.
func TestCaptureWithInjectsOtherHandles(t *testing.T) {
	ve := newVault(t)
	ve.add("existing/one", "value-number-one")
	r := ve.runEnv([]string{"HELPER_ECHO=wrapped-$EXISTING_ONE"}, nil, "capture", "derived/token", "--with", "existing/one", "--", helperBin)
	if r.code != 0 {
		t.Fatalf("capture --with: %s", r)
	}
	env, run := childEnv(t, ve, nil, "--with", "derived/token")
	if run.code != 0 || env["DERIVED_TOKEN"] != "wrapped-value-number-one" {
		t.Fatalf("captured value: %v (%s)", env, run)
	}
}

func TestCaptureCommandPolicyAppliesToWithBoundVar(t *testing.T) {
	ve := newVault(t)
	ve.add("existing/one", "value-number-one")
	r := ve.run(nil, "capture", "derived/token", "--with", "existing/one", "--", "sh", "-c", "echo $EXISTING_ONE")
	if r.code != 3 {
		t.Fatalf("want policy refusal: %s", r)
	}
	ls := ve.run(nil, "ls")
	if strings.Contains(ls.stdout, "derived/token") {
		t.Fatalf("should not store when Command Policy refused: %s", ls)
	}
}

// TestCaptureStderrRedacted proves capture reuses internal/run: stderr from
// the wrapped command goes through Redaction just like cpass run, while
// stdout is captured whole into the Vault and never echoed back to the
// caller. Command Policy is bypassed with the human-only --unsafe-allow (as
// the leak suite does) so this isolates Redaction from Command Policy.
func TestCaptureStderrRedacted(t *testing.T) {
	ve := newVault(t)
	ve.add("existing/one", "value-number-one")
	r := ve.runEnv([]string{"CPASS_TEST_TTY=1"}, nil, "capture", "derived/token", "--with", "existing/one", "--unsafe-allow", "--", "sh", "-c",
		`echo "$EXISTING_ONE" 1>&2; echo new-captured-value-1`)
	if r.code != 0 {
		t.Fatalf("capture: %s", r)
	}
	if strings.Contains(r.stderr, "value-number-one") {
		t.Fatalf("raw value leaked on stderr: %s", r)
	}
	if !strings.Contains(r.stderr, "[REDACTED:existing/one]") {
		t.Fatalf("stderr should carry the redaction marker: %s", r)
	}
	if strings.Contains(r.stdout, "new-captured-value-1") {
		t.Fatalf("captured stdout must not be echoed back to the caller: %s", r)
	}
	if strings.TrimSpace(r.stdout) != "derived/token" {
		t.Fatalf("capture's own stdout should be only the Handle: %s", r)
	}
}

func TestCaptureBindingFlags(t *testing.T) {
	ve := newVault(t)
	r := ve.run(nil, "capture", "demo/token", "--binding", "MY_TOKEN", "--", "sh", "-c", "echo tok_abcdef123456")
	if r.code != 0 {
		t.Fatalf("capture: %s", r)
	}
	ll := ve.run(nil, "ls", "-l")
	if !strings.Contains(ll.stdout, "MY_TOKEN") {
		t.Fatalf("binding override not applied: %s", ll)
	}
}

func TestCaptureShortValueRefused(t *testing.T) {
	ve := newVault(t)
	r := ve.run(nil, "capture", "demo/token", "--", "sh", "-c", "echo short")
	if r.code == 0 || !strings.Contains(r.stderr, "shorter than 8") {
		t.Fatalf("want short-value refusal: %s", r)
	}
}

// TestCaptureRedactsCpassKeyFromStderr is CLA-54's regression test for the
// capture-surface gap: cpass capture opens the Vault itself, via its own
// broker.OpenVault() call in openVault(e) (internal/cli/vaultcmds.go),
// before run.Run is ever invoked -- and with no --with here, Refs stays
// empty, exactly the shape the old guard (len(spec.Refs) > 0) could never
// see as "this invocation's own unlock source". Mirrors
// TestLeakCpassKeyItself (leak_test.go), but through cpass capture instead
// of cpass run, and asserting on stderr since capture's own stdout is
// reserved for the captured value.
func TestCaptureRedactsCpassKeyFromStderr(t *testing.T) {
	ve := newVault(t)
	script := `printf 'RAWKEY=[%s]\n' '` + ve.key + `' 1>&2; echo capture-body-value-1`
	r := ve.run(nil, "capture", "demo/token", "--", "sh", "-c", script)
	if r.code != 0 {
		t.Fatalf("capture: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, ve.key) {
		t.Fatalf("CPASS_KEY value leaked: %s", r)
	}
	if !strings.Contains(r.stderr, "[REDACTED:cpass/vault-key]") {
		t.Fatalf("CPASS_KEY marker missing: %s", r)
	}
}
