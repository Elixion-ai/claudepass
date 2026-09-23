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
		{"cat here-string reveals a bound variable", "cat <<< $STRIPE_LIVE", "cat <<< hello"},
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
