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

// TestPolicyRunRound2ReviewFindings is the fixer round's e2e proof, driven
// against a real built `cpass` binary, for every shape the round-2 review
// reported that a shell string can express: each refused shape must be
// refused through the actual `cpass run` invocation an Agent would make
// (Command Policy's real execution-gating surface, not just the unit-level
// Evaluate), the raw value must never reach stdout/stderr either way, and
// the paired benign shape alongside it must still run normally.
func TestPolicyRunRound2ReviewFindings(t *testing.T) {
	ve := leakVault(t)
	pairs := []struct {
		name             string
		refused, allowed string
	}{
		// command-policy:control-flow-keyword-bypass — a shell reserved
		// word in command-start position is never a real program name;
		// the real command inside (or the reveal in its body) must still
		// be checked, not merely relied on by Redaction downstream.
		{"if condition reads a secret file", "if cat .env; then true; fi", "if true; then echo hello; fi"},
		{"while condition reads a secret file", "while cat .env; do break; done", "while false; do echo hello; done"},
		{"until condition reads a secret file", "until cat .env; do break; done", "until true; do break; done"},
		{"if body reveals a bound variable", "if true; then echo $STRIPE_LIVE; fi", "if true; then echo hello; fi"},
		// command-policy:quoting-ansi-c-and-locale-strings
		{"ANSI-C quoting names a secret file", `cat $'.env'`, `echo $'hello'`},
		{"locale quoting names a secret file", `cat $".env"`, `echo $"hello"`},
		// command-policy:brace-expansion-hides-filename
		{"brace expansion names a secret file", "cat .{env,bashrc}", "echo .{txt,md}"},
		// command-policy:dynamic-command-name-not-resolved
		{"a whole variable naming a literal command reading a secret file", "x='cat .env'; $x", "x='echo hello'; $x"},
		// command-policy:reader-here-string-reveal-bypass
		// The allowed half runs its here-string under bash explicitly: sh is
		// dash on Linux, which has no <<< and fails with a syntax error.
		{"cat here-string reveals a bound variable", "cat <<< $STRIPE_LIVE", "bash -c 'cat <<< hello'"},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			r := sh(ve, p.refused)
			if r.code != 3 || !strings.HasPrefix(r.stderr, "cpass: refused: ") {
				t.Fatalf("refused case should be refused: %s", r)
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

// TestPolicyRunFindExecReadsSecretFileAsDirectArgv is
// command-policy:evaluate-missing-hook-per-word-wrapper-coverage's e2e
// proof at the direct-argv surface (no shell string at all): Evaluate
// previously special-cased only a fixed `wrappers` map plus `timeout`, so
// a reader behind `find -exec` — a wrapper on neither list — was never
// inspected when passed straight to `cpass run`, even though the
// byte-identical text handed to `cpass policy --hook` was already refused
// by hookWalk's own per-word scan.
func TestPolicyRunFindExecReadsSecretFileAsDirectArgv(t *testing.T) {
	ve := leakVault(t)
	r := ve.run(nil, "run", "--with", "stripe/live", "--", "find", ".", "-exec", "cat", ".env", ";")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("find -exec wrapping cat .env must be refused as direct argv: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}
	// Paired benign: find with nothing dangerous behind -exec, and no
	// -exec at all, must both stay allowed.
	r = ve.run(nil, "run", "--with", "stripe/live", "--", "find", ".", "-maxdepth", "0", "-exec", "echo", "hello", ";")
	if r.code != 0 {
		t.Fatalf("find -exec echo hello must stay allowed: %s", r)
	}
}

// TestPolicyRunProtectedDirsRelativePathAfterCd is
// command-policy:protecteddirs-relative-path-after-cd's e2e proof:
// underProtected's absolute-prefix check must still recognize a live
// file-Binding run directory referenced by a relative filename after a
// same-command `cd` into it. The check is purely a static textual prefix
// match against the run-dir root (ProtectedDirs), independent of whether
// any file actually exists there, so a fixed id stands in for the random
// one an Agent would otherwise have to discover live.
func TestPolicyRunProtectedDirsRelativePathAfterCd(t *testing.T) {
	ve := leakVault(t)
	rundir := filepath.Join(ve.home, "run", "deadbeefdeadbeef")
	r := sh(ve, "cd "+rundir+" && cat gcp-sa")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret file") {
		t.Fatalf("a relative reference after a same-command cd into the run dir should be refused: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}
	// Paired benign: cd-ing somewhere unrelated and reading a relative
	// file there must stay allowed.
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "notes.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = sh(ve, "cd "+elsewhere+" && cat notes.txt")
	if r.code != 0 {
		t.Fatalf("cd to an unrelated directory must not be refused: %s", r)
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

// TestPolicyRunIFSWordSplitting is command-policy:ifs-word-splitting-bypass's
// e2e proof (2026-09-22 audit, round 3), driven against a real built cpass
// binary: `cat${IFS}.env`/`cat$IFS.env` must not evade Command Policy by
// gluing a reader to a secret file's name through an unquoted $IFS/${IFS}
// reference — IFS's default value IS whitespace, so a real shell executes
// this as the two separate words "cat" and ".env".
func TestPolicyRunIFSWordSplitting(t *testing.T) {
	ve := leakVault(t)
	for _, script := range []string{`cat${IFS}.env`, `cat$IFS.env`} {
		r := sh(ve, script)
		if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
			t.Fatalf("%q should be refused as a secret-file read: %s", script, r)
		}
		if strings.Contains(r.stdout+r.stderr, leakVal) {
			t.Fatalf("leaked: %s", r)
		}
	}
	// Paired benign: the same splitting mechanism around nothing
	// dangerous stays allowed.
	r := sh(ve, `echo${IFS}hello`)
	if r.code != 0 || !strings.Contains(r.stdout, "hello") {
		t.Fatalf("IFS splitting around benign text should run normally: %s", r)
	}
}

// TestPolicyRunReadBuiltinAndFDRedirection is
// command-policy:read-builtin-and-fd-redirection-bypass's e2e proof
// (2026-09-22 audit, round 3), driven against a real built cpass binary,
// for both halves of the fix: the read/mapfile/readarray builtins loading
// a redirected secret file into a variable, and the `exec N< target; ...
// <&N` fd-alias idiom reading it back through a bound descriptor.
func TestPolicyRunReadBuiltinAndFDRedirection(t *testing.T) {
	ve := leakVault(t)
	refused := []string{
		`read -r line < .env`,
		`mapfile -t lines < .env`,
		`readarray -t lines < .env`,
		`exec 3< .env; cat <&3`,
		`exec {fd}< .env; cat <&$fd`,
	}
	for _, script := range refused {
		r := sh(ve, script)
		if r.code != 3 || !strings.HasPrefix(r.stderr, "cpass: refused: ") {
			t.Fatalf("%q should be refused: %s", script, r)
		}
		if strings.Contains(r.stdout+r.stderr, leakVal) {
			t.Fatalf("leaked: %s", r)
		}
	}
	// Paired benign shapes: the exact same mechanisms, pointed at
	// nothing dangerous, must still run.
	allowed := []string{
		// `read` exits non-zero on immediate EOF (an empty /dev/null),
		// which is real POSIX behavior having nothing to do with
		// Command Policy — `; true` keeps this an "allowed and runs"
		// assertion about the refusal, not about read's own exit code.
		`read -r line < /dev/null; true`,
		`exec 3< /dev/null; cat <&3`,
		// fd 9 isn't actually open in this shell, so real `cat` fails
		// with "Bad file descriptor" (unrelated to Command Policy);
		// `; true` keeps this an "allowed and runs" assertion about the
		// refusal, not about that unopened fd's own exit code.
		`cat <&9; true`,
	}
	for _, script := range allowed {
		r := sh(ve, script)
		if r.code != 0 {
			t.Fatalf("%q should run normally: %s", script, r)
		}
	}
}

// TestPolicyRunShellBehindUnenumeratedWrapper is
// command-policy:evaluate-shell-behind-unenumerated-wrapper-parity-gap's
// e2e proof (2026-09-22 audit, round 3), driven against a real built cpass
// binary: Evaluate's per-word fallback must resolve a shell invocation
// behind ANY wrapper program, not only the `wrappers` map's fixed list —
// proved with a synthetic `exec "$@"` passthrough shim standing in for the
// whole unenumerable class (chroot, unshare, ssh host, script -qc, setsid,
// systemd-run, nsenter, valgrind --, strace -f, docker exec, ...), in both
// argv and shell-string form.
func TestPolicyRunShellBehindUnenumeratedWrapper(t *testing.T) {
	ve := leakVault(t)
	dir := t.TempDir()
	shim := filepath.Join(dir, "passthrough-shim")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexec \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Argv form: the shim is argv[0], the real shell invocation follows.
	r := ve.run(nil, "run", "--with", "stripe/live", "--", shim, "sh", "-c", "cat .env")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("a shell invocation behind an unenumerated wrapper (argv form) must be refused: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}

	// Shell-string form: the whole wrapped invocation is itself one
	// shell string handed to `cpass run -- sh -c '...'`.
	r = sh(ve, shim+" sh -c 'cat .env'")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("a shell invocation behind an unenumerated wrapper (shell-string form) must be refused: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}

	// Paired benign: the same wrapper shape, pointed at a shell
	// invocation with nothing dangerous in it, must still run — proving
	// the real content is being checked, not every wrapper shape refused
	// on sight.
	r = ve.run(nil, "run", "--with", "stripe/live", "--", shim, "sh", "-c", "echo hello")
	if r.code != 0 || !strings.Contains(r.stdout, "hello") {
		t.Fatalf("a safe shell invocation behind the same wrapper must still run: %s", r)
	}
}

// TestPolicyRunReaderBehindUnenumeratedWrapper is CLA-101's own review
// finding (round 2)'s e2e proof, driven against a real built cpass
// binary: CLA-101's original fix required a genuine trigger word
// immediately before a reader-name word, which — unlike its intended
// aws/kubectl coincidental-subcommand fix — also silently stopped
// catching a reader behind ANY other wrapper program this package's own
// `wrappers` map doesn't enumerate, even though its argv text plainly,
// unambiguously names the reader right there. Proved the same way
// TestPolicyRunShellBehindUnenumeratedWrapper above proves the parallel
// shell case: a synthetic `exec "$@"` passthrough shim standing in for
// the whole unenumerable class (docker exec, chroot, strace, setsid,
// unshare, stdbuf, ...), in both argv and shell-string form — this is
// the actual execution gate `cpass run` and the MCP server's
// run_with_secrets/capture use, not only the advisory PreToolUse hook.
func TestPolicyRunReaderBehindUnenumeratedWrapper(t *testing.T) {
	ve := leakVault(t)
	dir := t.TempDir()
	shim := filepath.Join(dir, "passthrough-shim")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexec \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notes, []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Argv form: the shim is argv[0], the real reader invocation follows.
	r := ve.run(nil, "run", "--with", "stripe/live", "--", shim, "cat", ".env")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("a reader invocation behind an unenumerated wrapper (argv form) must be refused: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}

	// Shell-string form: the whole wrapped invocation is itself one
	// shell string handed to `cpass run -- sh -c '...'`.
	r = sh(ve, shim+" cat .env")
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("a reader invocation behind an unenumerated wrapper (shell-string form) must be refused: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}

	// Paired benign: the same wrapper shape, pointed at a real benign
	// file, must still run — proving the real argument is being checked,
	// not every wrapper shape refused on sight.
	r = ve.run(nil, "run", "--with", "stripe/live", "--", shim, "cat", notes)
	if r.code != 0 || !strings.Contains(r.stdout, "hi") {
		t.Fatalf("a reader invocation behind the same wrapper reading a benign file should run normally: %s", r)
	}
}

// TestPolicyRunSecretFileGlobExpansion is
// command-policy:shell-glob-expansion-hides-filename's e2e proof
// (2026-09-22 audit, round 3), driven against a real built cpass binary
// with a REAL .env file on disk: a real shell's own filename globbing
// expands a glob-shaped argument (`.en?`, `.e*`) against files that
// actually exist in the command's cwd before the reading program ever
// starts, so this must be refused the same way the literal spelling
// already is.
func TestPolicyRunSecretFileGlobExpansion(t *testing.T) {
	ve := leakVault(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("STRIPE_LIVE=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, glob := range []string{".en?", ".e*"} {
		r := sh(ve, "cd "+dir+" && cat "+glob)
		if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
			t.Fatalf("glob %q resolving to a real secret file must be refused: %s", glob, r)
		}
		if strings.Contains(r.stdout+r.stderr, leakVal) {
			t.Fatalf("leaked: %s", r)
		}
	}
	// Paired benign: a glob pattern matching only a benign file in the
	// same real directory must still run.
	r := sh(ve, "cd "+dir+" && cat *.txt")
	if r.code != 0 || !strings.Contains(r.stdout, "hi") {
		t.Fatalf("a glob matching only a benign file should run normally: %s", r)
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

// TestPolicyRunWriteThenRun is CLA-103's write-then-run pattern at the
// cpass run e2e layer, driven against a real built cpass binary with
// real execution: writing a script via a heredoc-to-file redirect and
// running it in the same wrapped command must not be refused just
// because the file genuinely isn't on disk yet when Evaluate runs,
// before the child process (which does the actual writing) has even
// started — and the underlying script must still genuinely run,
// this package's own core use case.
func TestPolicyRunWriteThenRun(t *testing.T) {
	ve := leakVault(t)
	dir := t.TempDir()
	safe := "cd " + dir + " && cat > t.sh <<'EOF'\n#!/bin/sh\necho ok\nEOF\nbash t.sh"
	r := ve.run(nil, "run", "--with", "stripe/live", "--", "bash", "-c", safe)
	if r.code != 0 {
		t.Fatalf("a benign script written then run in one call must still run: %s", r)
	}
	if !strings.Contains(r.stdout, "ok") {
		t.Fatalf("the written script's own output should reach stdout: %s", r)
	}
	// Paired bypass: a script written then run that itself reads a secret
	// file is still refused.
	dangerous := "cd " + dir + " && cat > t2.sh <<'EOF'\ncat .env\nEOF\nbash t2.sh"
	r = ve.run(nil, "run", "--with", "stripe/live", "--", "bash", "-c", dangerous)
	if r.code != 3 || !strings.Contains(r.stderr, "Secret-bearing file") {
		t.Fatalf("a dangerous script written then run must still be refused: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}
}

// TestPolicyRunCommandCdInvalidatesWriteThenRun is CLA-103's review fix:
// the write-then-run `cd`-invalidation safety valve only recognized a
// BARE `cd`, missing `command cd`/`builtin cd` — both ordinary, working
// shell syntax. Reproduced against real execution at this e2e layer,
// mirroring the review's own live finding exactly: a benign heredoc is
// written to one directory, then `command cd`/`builtin cd` moves into a
// SECOND directory that already holds a differently-owned, genuinely
// dangerous same-named script — before this fix, Command Policy resolved
// the later `bash t.sh` against the tracked BENIGN body from the first
// write (believing it had vetted what would run) and let cpass actually
// execute the real, never-inspected file at the new directory
// unchecked — a full bypass of the write-then-run guarantee, not merely
// a missed refusal. The real script prints a marker no refused run could
// ever produce, so a regression here is caught even if the exit code
// were ever accidentally relaxed.
func TestPolicyRunCommandCdInvalidatesWriteThenRun(t *testing.T) {
	ve := leakVault(t)
	dir := t.TempDir()
	realtarget := filepath.Join(dir, "realtarget")
	if err := os.MkdirAll(realtarget, 0o755); err != nil {
		t.Fatal(err)
	}
	// The real, pre-existing file at the cd target: genuinely dangerous
	// (reads a Secret-bearing file) and, if actually run unchecked, prints
	// a marker proving so.
	if err := os.WriteFile(filepath.Join(realtarget, "t.sh"), []byte("cat .env\necho REAL_EXECUTION_RAN_UNCHECKED_SCRIPT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realtarget, ".env"), []byte("DUMMY=not-the-bound-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prefixes := []string{"command", "builtin"}
	for _, prefix := range prefixes {
		t.Run(prefix+" cd", func(t *testing.T) {
			// The heredoc write itself is to a DIFFERENT path (dir/t.sh,
			// benign) than the one the command actually cds into and runs
			// (realtarget/t.sh, dangerous) — exactly the review's own
			// shape, not a simplified same-path stand-in.
			cmd := "cd " + dir + " && cat > t.sh <<'EOF'\necho benign\nEOF\n" + prefix + " cd " + realtarget + " && bash t.sh"
			r := ve.run(nil, "run", "--with", "stripe/live", "--", "bash", "-c", cmd)
			if r.code != 3 || !strings.Contains(r.stderr, "invocation shape can't be checked statically") {
				t.Fatalf("%s cd between a write-then-run write and its run must invalidate the tracked body and fail closed: %s", prefix, r)
			}
			if strings.Contains(r.stdout, "REAL_EXECUTION_RAN_UNCHECKED_SCRIPT") {
				t.Fatalf("%s cd let the real, unvetted script at the new directory actually execute: %s", prefix, r)
			}
			if strings.Contains(r.stdout+r.stderr, leakVal) {
				t.Fatalf("leaked: %s", r)
			}
		})
	}
	// Sanity: a BARE cd between the same write and run is still refused
	// the same way (no regression from this fix), and the ordinary,
	// no-intervening-cd write-then-run case still genuinely runs.
	t.Run("bare cd (no regression)", func(t *testing.T) {
		cmd := "cd " + dir + " && cat > t2.sh <<'EOF'\necho benign\nEOF\ncd " + realtarget + " && bash t2.sh"
		r := ve.run(nil, "run", "--with", "stripe/live", "--", "bash", "-c", cmd)
		if r.code != 3 || !strings.Contains(r.stderr, "invocation shape can't be checked statically") {
			t.Fatalf("a bare cd between write and run must still fail closed: %s", r)
		}
	})
	t.Run("no intervening cd still runs", func(t *testing.T) {
		cmd := "cd " + dir + " && cat > t3.sh <<'EOF'\necho benign\nEOF\nbash t3.sh"
		r := ve.run(nil, "run", "--with", "stripe/live", "--", "bash", "-c", cmd)
		if r.code != 0 || !strings.Contains(r.stdout, "benign") {
			t.Fatalf("write-then-run with no intervening cd must still genuinely run: %s", r)
		}
	})
}

// TestPolicyRunLaterOverwriteInvalidatesWriteThenRun is CLA-103's round-2
// review finding, reproduced against real execution exactly the way the
// review itself reported it: a benign heredoc write to a path, followed —
// LATER IN THE SAME wrapped command, with no intervening cd — by a plain
// (non-heredoc) `>` redirect that silently replaces that identical path's
// real on-disk content with something never checked at all, then a shell
// invocation of that same path. Before this fix, ev.written kept
// certifying the FIRST (benign) write's tracked body even though the
// SECOND, unrecognized write is what the file actually held by the time
// bash ran it — so cpass genuinely executed the real, never-inspected
// script content unchecked. The real script prints a marker no refused
// run could ever produce, so a regression here is caught even if the exit
// code were ever accidentally relaxed — the same evidentiary standard
// TestPolicyRunCommandCdInvalidatesWriteThenRun above already uses.
func TestPolicyRunLaterOverwriteInvalidatesWriteThenRun(t *testing.T) {
	ve := leakVault(t)
	dir := t.TempDir()
	cases := []struct {
		name    string
		rewrite string
	}{
		{"a later plain > redirect", "echo 'echo REAL_EXECUTION_RAN_UNCHECKED_SCRIPT' > t.sh"},
		{"a later plain >> redirect", "echo 'echo REAL_EXECUTION_RAN_UNCHECKED_SCRIPT' >> t.sh"},
		{"a later bare tee with no heredoc", "tee t.sh <<<'echo REAL_EXECUTION_RAN_UNCHECKED_SCRIPT'"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd := "cd " + dir + " && cat > t.sh <<'EOF'\necho benign\nEOF\n" + c.rewrite + "\nbash t.sh"
			r := ve.run(nil, "run", "--with", "stripe/live", "--", "bash", "-c", cmd)
			if r.code != 3 || !strings.Contains(r.stderr, "invocation shape can't be checked statically") {
				t.Fatalf("a later, unrecognized write to the identical path must invalidate the tracked heredoc body and fail closed: %s", r)
			}
			if strings.Contains(r.stdout, "REAL_EXECUTION_RAN_UNCHECKED_SCRIPT") {
				t.Fatalf("the later, never-inspected write's real content was actually executed unchecked: %s", r)
			}
			if strings.Contains(r.stdout+r.stderr, leakVal) {
				t.Fatalf("leaked: %s", r)
			}
		})
	}
	// Sanity: an unrelated write to a DIFFERENT path in between leaves the
	// run's own tracked body alone, and the ordinary write-then-run case
	// keeps genuinely running (no regression from this fix).
	t.Run("an unrelated write to a different path is unaffected", func(t *testing.T) {
		cmd := "cd " + dir + " && cat > t2.sh <<'EOF'\necho benign\nEOF\necho unrelated > other.txt\nbash t2.sh"
		r := ve.run(nil, "run", "--with", "stripe/live", "--", "bash", "-c", cmd)
		if r.code != 0 || !strings.Contains(r.stdout, "benign") {
			t.Fatalf("an unrelated write to a different path must not invalidate the run's own tracked body: %s", r)
		}
	})
}

// TestPolicyRunXtraceStillRefused is CLA-103's own stated scope: the
// hook-only shell-tracing allowlist (Input.TraceAllowlist) must never
// leak into cpass run's own Evaluate call, which runs with real Bound
// Secret values already sitting in the child's environment — unlike
// the PreToolUse hook, which allows this (TestPolicyHookXtraceAllowlist,
// internal/e2e/policy_hook_test.go).
func TestPolicyRunXtraceStillRefused(t *testing.T) {
	ve := leakVault(t)
	r := ve.run(nil, "run", "--with", "stripe/live", "--", "bash", "-c", "set -x; echo hi")
	if r.code != 3 || !strings.Contains(r.stderr, "echoes expanded variables") {
		t.Fatalf("set -x must still be refused under cpass run: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, leakVal) {
		t.Fatalf("leaked: %s", r)
	}
}
