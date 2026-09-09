package e2e

import (
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
