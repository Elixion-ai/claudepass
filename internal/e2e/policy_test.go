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

// TestPolicyRunShellInvocationHeredocDoesNotShadowCString is CLA-62's
// review fix at the cpass run e2e layer: a -c STRING or script-by-path
// argument paired with an attached heredoc must still have that -c/script
// content checked, exactly like TestPolicyRunShellInvocationShapes above —
// the heredoc is just stdin data for the invocation, not a decoy that can
// hide a dangerous invocation behind a benign-looking body. Before this fix
// the heredoc's body was checked instead of -c's/the script's own content,
// a full, silent (exit 0, no refusal) bypass reachable from a single raw
// Bash call, with no `cpass run` wrapping needed.
func TestPolicyRunShellInvocationHeredocDoesNotShadowCString(t *testing.T) {
	ve := leakVault(t)
	dir := t.TempDir()

	// The exact shape reported: a nested `bash -c "cat .env"` whose own
	// heredoc is a decoy, reached through `sh -c` the way cpass run
	// itself parses its wrapped shell command.
	r := sh(ve, "bash -c \"cat .env\" <<'EOF'\necho decoy\nEOF\n")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("a dangerous -c string paired with a benign heredoc must still be refused: %s", r)
	}

	// The exact live-verified exploit: `cpass run -- bash exploit.sh`
	// where exploit.sh itself is `bash -c "cat .env" <<'EOF' ... EOF`.
	exploit := filepath.Join(dir, "exploit.sh")
	exploitBody := "bash -c \"cat .env\" <<'EOF'\necho this-heredoc-body-is-a-decoy\nEOF\n"
	if err := os.WriteFile(exploit, []byte(exploitBody), 0o755); err != nil {
		t.Fatal(err)
	}
	r = ve.run(nil, "run", "--with", "stripe/live", "--", "bash", exploit)
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("the exact CLA-62 review exploit script must be refused: %s", r)
	}

	// A dangerous script-by-path paired with a benign heredoc must be
	// refused the same way.
	dangerous := filepath.Join(dir, "dangerous.sh")
	if err := os.WriteFile(dangerous, []byte("#!/bin/sh\ncat .env\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r = sh(ve, "bash "+dangerous+" <<'EOF'\necho decoy\nEOF\n")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("a dangerous script-by-path paired with a benign heredoc must still be refused: %s", r)
	}

	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}
}

// TestPolicyRunShellInvocationCombinedOptionOrdering is CLA-62's review-fix
// e2e proof: `bash -co pipefail 'cat .env'` and `bash -oc pipefail 'cat
// .env'` (either letter order, either sign) must have the real command
// checked, not the -o value that happens to sit next to 'c' in the group.
// Live-reproduced before this fix: shellCommandString returned "pipefail" as
// the -c string the instant it saw 'c' anywhere in a combined group, so the
// actual `cat .env` never got evaluated and its content reached stdout
// unrefused and unredacted.
func TestPolicyRunShellInvocationCombinedOptionOrdering(t *testing.T) {
	ve := leakVault(t)
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"-co: o's value first, c's string is the real command", []string{"bash", "-co", "pipefail", "cat .env"}, true},
		{"-oc: same result with the letters swapped", []string{"bash", "-oc", "pipefail", "cat .env"}, true},
		{"+co: plus form", []string{"bash", "+co", "pipefail", "cat .env"}, true},
		{"+oc: plus form, letters swapped", []string{"bash", "+oc", "pipefail", "cat .env"}, true},
		// Paired benign shapes: the same combined-option groups, pointed
		// at a command with nothing dangerous in it, must still run.
		{"-co with a safe command is allowed", []string{"bash", "-co", "pipefail", "echo hello"}, false},
		{"-oc with a safe command is allowed", []string{"bash", "-oc", "pipefail", "echo hello"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"run", "--with", "stripe/live", "--"}, c.argv...)
			r := ve.run(nil, args...)
			if c.refused {
				if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
					t.Fatalf("the real command must be checked, not the -o value beside it: %s", r)
				}
			} else if r.code != 0 {
				t.Fatalf("a safe command behind the same combined options must still run: %s", r)
			}
			if strings.Contains(r.stdout+r.stderr, leakVal) {
				t.Fatalf("leaked: %s", r)
			}
		})
	}
}

// TestPolicyRunHeredocUnquotedExpansionAnyProgram is CLA-61's review-fix e2e
// proof: a real shell expands an UNQUOTED heredoc delimiter's body — command
// substitutions and parameter expansions alike — before it ever reaches the
// reading program's stdin, so this must be caught regardless of which
// program the heredoc is attached to, not only a shell. Live-reproduced
// before this fix: `cat <<EOF
// $(cat .env)
// EOF` reached stdout unrefused and unredacted, since splitCommands stored a
// heredoc's body as opaque text and never populated its subs.
func TestPolicyRunHeredocUnquotedExpansionAnyProgram(t *testing.T) {
	ve := leakVault(t)

	r := sh(ve, "cat <<EOF\n$(cat .env)\nEOF\n")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("an unquoted heredoc's command substitution must be evaluated regardless of program: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}

	// The same substitution, attached to a program that isn't a reader at
	// all: the fix walks every word's subs unconditionally.
	r = sh(ve, "wc -l <<EOF\n$(cat .env)\nEOF\n")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("the substitution must still be caught behind a non-reader program: %s", r)
	}

	// Paired benign: the quoted-delimiter counterpart of the exact same
	// body is genuinely inert data in a real shell — .env is never read,
	// only the literal text "$(cat .env)" is ever printed.
	r = sh(ve, "cat <<'EOF'\n$(cat .env)\nEOF\n")
	if r.code != 0 || !strings.Contains(r.stdout, "$(cat .env)") {
		t.Fatalf("a quoted-delimiter heredoc's body is inert data and must run: %s", r)
	}

	// A reveal-only bound variable in an unquoted heredoc body resolves
	// to the Secret's real value before cat (given no file operand) ever
	// starts — exactly like `echo $STRIPE_LIVE`.
	r = sh(ve, "cat <<EOF\n$STRIPE_LIVE\nEOF\n")
	if r.code != 3 {
		t.Fatalf("an unquoted heredoc revealing a bound variable must be refused: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}

	// Paired benign: the quoted-delimiter counterpart never expands
	// $STRIPE_LIVE — cat just prints the four literal characters.
	r = sh(ve, "cat <<'EOF'\n$STRIPE_LIVE\nEOF\n")
	if r.code != 0 || !strings.Contains(r.stdout, "$STRIPE_LIVE") {
		t.Fatalf("a quoted-delimiter heredoc naming a bound variable as literal text must run: %s", r)
	}

	// Paired benign: an unquoted heredoc with nothing dangerous in it at
	// all must stay allowed.
	r = sh(ve, "cat <<EOF\nhello world\nEOF\n")
	if r.code != 0 || !strings.Contains(r.stdout, "hello world") {
		t.Fatalf("a benign heredoc body must run normally: %s", r)
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
