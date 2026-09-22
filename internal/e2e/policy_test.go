package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyRefusedAndAllowedPairs(t *testing.T) {
	ve := leakVault(t)
	pairs := []struct {
		name             string
		refused, allowed string
	}{
		{"echo", `echo $STRIPE_LIVE`, `echo hello`},
		{"printf", `printf '%s\n' "$STRIPE_LIVE"`, `printf '%s\n' hello`},
		{"env", `env`, `env FOO=1 true`},
		{"printenv", `printenv STRIPE_LIVE`, `test -n "$STRIPE_LIVE"`},
		{"set", `set`, `set -e; true`},
		{"set -x", `set -x; true`, `set -u; true`},
		{"export", `export -p`, `export FOO=1; true`},
		{"taint", `X=$STRIPE_LIVE; echo $X`, `X=plain; echo $X`},
		{"nested shell", `bash -c 'echo $STRIPE_LIVE'`, `bash -c 'echo ok'`},
		{"header use", `printf "%s" "$STRIPE_LIVE" | base64`, `true -H "Authorization: Bearer $STRIPE_LIVE"`},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			r := sh(ve, p.refused)
			if r.code != 3 || !strings.HasPrefix(r.stderr, "cpass: refused: ") || strings.Count(r.stderr, "\n") != 1 {
				t.Fatalf("refused case should exit 3 with one line: %s", r)
			}
			if strings.Contains(r.stdout+r.stderr, leakVal) {
				t.Fatalf("leaked: %s", r)
			}
			r = sh(ve, p.allowed)
			if r.code != 0 {
				t.Fatalf("allowed case should run: %s", r)
			}
		})
	}
}

// TestPolicyRunRefusesSecretFileReadsAndRawLiterals is CLA-38's e2e proof
// that cpass run applies the same secret-file-glob and raw-literal rules
// the PreToolUse hook (cpass policy --hook) already applied — the parity
// gap `docs/THREATS.md` and internal/policy's package doc comment used to
// describe. It drives `cpass run` directly, not through sh -c, since the
// gap was specifically that Evaluate (not EvaluateHook) skipped these
// rules.
func TestPolicyRunRefusesSecretFileReadsAndRawLiterals(t *testing.T) {
	ve := leakVault(t)
	pairs := []struct {
		name    string
		argv    []string
		refused bool
		want    string // substring cpass's stderr must contain when refused
	}{
		{"cat dotenv", []string{"cat", ".env"}, true, "Secret-bearing file"},
		{"less pem file", []string{"less", "id_rsa.pem"}, true, "Secret-bearing file"},
		{"cat credentials json", []string{"cat", "credentials.json"}, true, "Secret-bearing file"},
		{"source dotenv via shell", []string{"sh", "-c", "source .env"}, true, "Secret-bearing file"},
		{"raw secret literal", []string{"curl", "-H",
			"Authorization: Bearer sk_live_51H8xJ2eZvKYlo2CTcpassrunliteralVALUEab"}, true, "Secret-shaped value"},
		// Keep `cpass run -- cat /etc/hosts` allowed: an ordinary file
		// read that doesn't match any Secret-bearing glob must not be
		// refused just because cpass run now applies these rules too.
		{"cat unrelated file", []string{"cat", "/etc/hosts"}, false, ""},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			args := append([]string{"run", "--with", "stripe/live", "--"}, p.argv...)
			r := ve.run(nil, args...)
			if p.refused {
				if r.code != 3 || !strings.HasPrefix(r.stderr, "cpass: refused: ") {
					t.Fatalf("want a Command Policy refusal: %s", r)
				}
				if !strings.Contains(r.stderr, p.want) {
					t.Fatalf("stderr should mention %q: %s", p.want, r)
				}
			} else if r.code != 0 {
				t.Fatalf("allowed case should run: %s", r)
			}
			if strings.Contains(r.stdout+r.stderr, leakVal) {
				t.Fatalf("leaked: %s", r)
			}
		})
	}
}

// TestPolicyRunShellInvocationShapes is CLA-62's e2e acceptance: a shell
// option before -c, and a script-by-path invocation, must both still have
// their content evaluated instead of passing through unchecked — this is
// what keeps `cpass run -- bash script.sh` working for a script that does
// nothing dangerous, the core use case, rather than refusing every
// script-by-path invocation outright.
func TestPolicyRunShellInvocationShapes(t *testing.T) {
	ve := leakVault(t)
	dir := t.TempDir()
	dangerous := filepath.Join(dir, "dangerous.sh")
	if err := os.WriteFile(dangerous, []byte("#!/bin/sh\ncat .env\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(dir, "safe.sh")
	if err := os.WriteFile(safe, []byte("#!/bin/sh\necho hello\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := ve.run(nil, "run", "--with", "stripe/live", "--", "bash", dangerous)
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("a script reading .env must be refused: %s", r)
	}
	r = ve.run(nil, "run", "--with", "stripe/live", "--", "bash", safe)
	if r.code != 0 {
		t.Fatalf("a script that does nothing dangerous must still run: %s", r)
	}
	// Docker's own SHELL directive shape: a flag before -c must not skip
	// checking -c's content.
	r = ve.run(nil, "run", "--with", "stripe/live", "--", "bash", "-o", "pipefail", "-c", "cat .env")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("a flag before -c must not skip checking -c's content: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}
}

func TestPolicyProcEnviron(t *testing.T) {
	ve := leakVault(t)
	r := ve.run(nil, "run", "--with", "stripe/live", "--", "cat", "/proc/self/environ")
	if r.code != 3 || !strings.Contains(r.stderr, "environment file") {
		t.Fatalf("proc environ: %s", r)
	}
	r = ve.run(nil, "run", "--with", "stripe/live", "--", "cat", "/dev/null")
	if r.code != 0 {
		t.Fatalf("cat /dev/null should be allowed: %s", r)
	}
}

func TestPolicyDirectPrintenv(t *testing.T) {
	ve := leakVault(t)
	r := ve.run(nil, "run", "--with", "stripe/live", "--", "printenv")
	if r.code != 3 {
		t.Fatalf("printenv: %s", r)
	}
}

func TestUnsafeAllowNeedsTerminal(t *testing.T) {
	ve := leakVault(t)
	r := ve.run(nil, "run", "--unsafe-allow", "--with", "stripe/live", "--", "sh", "-c", "echo $STRIPE_LIVE")
	if r.code != 3 || !strings.Contains(r.stderr, "needs a terminal") {
		t.Fatalf("without terminal: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}
	// With a (test-faked) terminal the human may override; Redaction still applies.
	r = ve.runEnv([]string{"CPASS_TEST_TTY=1"}, nil, "run", "--unsafe-allow", "--with", "stripe/live", "--", "sh", "-c", "echo $STRIPE_LIVE")
	if r.code != 0 || !strings.Contains(r.stdout, "[REDACTED:stripe/live]") {
		t.Fatalf("with terminal: %s", r)
	}
}

func TestProductionBinaryHasNoTestHooks(t *testing.T) {
	// The release build (no e2e tag) must ignore CPASS_TEST_STDIN and CPASS_TEST_TTY.
	bin := buildRelease(t)
	ve := newVault(t)
	r := ve.runBin(bin, []string{"CPASS_TEST_STDIN=1"}, []byte("value-from-agent\n"), "add", "x/y")
	if r.code == 0 || !strings.Contains(r.stderr, "cpass capture") {
		t.Fatalf("release add must refuse piped stdin: %s", r)
	}
	ve.add("stripe/live", leakVal)
	r = ve.runBin(bin, []string{"CPASS_TEST_TTY=1"}, nil, "run", "--unsafe-allow", "--with", "stripe/live", "--", "true")
	if r.code != 3 || !strings.Contains(r.stderr, "needs a terminal") {
		t.Fatalf("release unsafe-allow must refuse without a real terminal: %s", r)
	}
}
