package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

var bound = []Var{{"STRIPE_LIVE", vault.BindEnv}, {"GCP_SA", vault.BindFile}}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		// allowed
		{"plain command", []string{"ls", "-la"}, false},
		{"echo literal", []string{"echo", "hello"}, false},
		{"echo unbound var in shell", []string{"sh", "-c", "echo $HOME"}, false},
		{"use in header", []string{"sh", "-c", `curl -H "Authorization: Bearer $STRIPE_LIVE" https://x`}, false},
		{"test -n", []string{"sh", "-c", `test -n "$STRIPE_LIVE" && echo ok`}, false},
		{"env with command", []string{"env", "FOO=1", "true"}, false},
		{"env -i cmd", []string{"env", "-i", "PATH=/bin", "true"}, false},
		{"set -e", []string{"bash", "-c", "set -e; true"}, false},
		{"export assignment", []string{"sh", "-c", "export FOO=bar; true"}, false},
		{"file used by tool", []string{"sh", "-c", `gcloud auth activate-service-account --key-file="$GCP_SA"`}, false},
		{"wc on file via redirect", []string{"sh", "-c", `wc -c < "$GCP_SA"`}, false},
		{"test -f file", []string{"sh", "-c", `test -f "$GCP_SA" && echo present`}, false},
		{"cat unrelated file", []string{"cat", "/etc/hosts"}, false},
		{"grep unrelated", []string{"sh", "-c", "grep foo bar.txt"}, false},
		{"timeout wrapper ok", []string{"timeout", "5", "true"}, false},
		{"literal dollar in argv is not a shell", []string{"echo", "$STRIPE_LIVE"}, false},
		// refused: secret-bearing file reads (CLA-38 — same rule EvaluateHook applies)
		{"cat dotenv", []string{"cat", ".env"}, true},
		{"cat dotenv via home var literal", []string{"cat", "$HOME/.env"}, true},
		{"less pem file", []string{"less", "server.pem"}, true},
		{"head id_rsa", []string{"head", "id_rsa"}, true},
		{"cat credentials json", []string{"cat", "credentials.json"}, true},
		{"cat dotenv in shell", []string{"sh", "-c", "cat .env"}, true},
		{"source dotenv in shell", []string{"sh", "-c", "source .env"}, true},
		{"dot source dotenv in shell", []string{"sh", "-c", ". .env"}, true},
		{"cat dotenv in nested shell", []string{"sh", "-c", `bash -c "cat .env"`}, true},
		// CLA-61: input redirection, a literal-value variable, and a real
		// backslash-newline continuation are all just as reachable a
		// bypass as a direct `cat .env` and must be refused the same way.
		{"cat dotenv via input redirection", []string{"sh", "-c", "cat < .env"}, true},
		{"cat dotenv via literal-value variable", []string{"sh", "-c", `f=.env; cat "$f"`}, true},
		{"cat dotenv via backslash-newline continuation", []string{"sh", "-c", "ca\\\nt .env"}, true},
		{"source dotenv via literal-value variable", []string{"sh", "-c", `f=.env; source "$f"`}, true},
		// Reopened CLA-61 gap: an unquoted ${f} was tokenized as
		// brace-grouping separators ("cat $" / "f"), so the literal
		// variable was never resolved back to .env for this idiomatic,
		// extremely common spelling — only the quoted "$f" form above was
		// covered.
		{"cat dotenv via unquoted-braces literal variable", []string{"sh", "-c", `f=.env; cat ${f}`}, true},
		// CLA-65: a public key or a template dotenv was never meant to be
		// Vaulted, so these must not be refused with a dead-end "use
		// cpass run instead".
		{"cat id_rsa pub is not a secret", []string{"cat", "id_rsa.pub"}, false},
		{"cat dotenv example is not a secret", []string{"cat", ".env.example"}, false},
		{"cat dotenv sample is not a secret", []string{"cat", ".env.sample"}, false},
		// CLA-66: indirect expansion must be caught up front by Evaluate,
		// the same as the direct $STRIPE_LIVE form.
		{"indirect expansion of a bound variable", []string{"sh", "-c", `x=STRIPE_LIVE; echo "${!x}"`}, true},
		// Reopened CLA-66 gap, same root cause CLA-61 fixed in split.go:
		// the ticket's own literal reproduction is unquoted, and hit the
		// same {/} mis-tokenization bug — only the quoted variant was
		// ever covered, which masked it (Redaction still caught the
		// bound value downstream in the live cpass run path, but this
		// ticket's own acceptance criterion — refused up front by
		// Evaluate — was unmet for the exact command it describes).
		{"indirect expansion of a bound variable, unquoted braces", []string{"sh", "-c", `x=STRIPE_LIVE; echo ${!x}`}, true},
		// refused: raw Secret-shaped literal (CLA-38 — reuses internal/detect)
		{"raw secret literal in argv", []string{"curl", "-H", "Authorization: Bearer sk_live_51H8xJ2eZvKYlo2CTargvVALUEabcdefgh"}, true},
		{"raw secret literal in shell string", []string{"sh", "-c", `curl -H "Authorization: Bearer sk_live_51H8xJ2eZvKYlo2CTshellVALUEabcdefgh"`}, true},
		// refused
		{"printenv", []string{"printenv"}, true},
		{"printenv var", []string{"printenv", "STRIPE_LIVE"}, true},
		{"env bare", []string{"env"}, true},
		{"env -0", []string{"env", "-0"}, true},
		{"/usr/bin/env bare", []string{"/usr/bin/env"}, true},
		{"echo bound in shell", []string{"sh", "-c", "echo $STRIPE_LIVE"}, true},
		{"echo bound braces quoted", []string{"bash", "-c", `echo "${STRIPE_LIVE}"`}, true},
		{"printf bound", []string{"sh", "-c", `printf '%s\n' "$STRIPE_LIVE"`}, true},
		{"after &&", []string{"sh", "-c", "true && echo $STRIPE_LIVE"}, true},
		{"in pipeline", []string{"sh", "-c", "echo $STRIPE_LIVE | base64"}, true},
		{"taint via assignment", []string{"sh", "-c", "X=$STRIPE_LIVE; echo $X"}, true},
		{"taint via export", []string{"sh", "-c", "export X=$STRIPE_LIVE; echo $X"}, true},
		{"nested shell", []string{"sh", "-c", `bash -c 'echo $STRIPE_LIVE'`}, true},
		{"eval", []string{"sh", "-c", `eval "echo \$STRIPE_LIVE"`}, true},
		{"command substitution", []string{"sh", "-c", "true $(printenv STRIPE_LIVE)"}, true},
		{"backtick substitution", []string{"sh", "-c", "x=`echo $STRIPE_LIVE`; true"}, true},
		{"env inside shell", []string{"sh", "-c", "env | grep STRIPE"}, true},
		{"set bare", []string{"sh", "-c", "set"}, true},
		{"set -x", []string{"sh", "-c", "set -x; true"}, true},
		{"sh -xc", []string{"sh", "-xc", "true"}, true},
		{"export bare", []string{"sh", "-c", "export"}, true},
		{"export -p", []string{"bash", "-c", "export -p"}, true},
		{"declare -p", []string{"bash", "-c", "declare -p"}, true},
		{"compgen -v", []string{"bash", "-c", "compgen -v"}, true},
		{"proc self environ", []string{"cat", "/proc/self/environ"}, true},
		{"proc pid environ in shell", []string{"sh", "-c", "tr '\\0' '\\n' < /proc/$$/environ"}, true},
		{"strings proc environ", []string{"strings", "/proc/1234/environ"}, true},
		{"cat file binding", []string{"sh", "-c", `cat "$GCP_SA"`}, true},
		{"base64 file binding", []string{"sh", "-c", `base64 $GCP_SA`}, true},
		{"cp file binding", []string{"sh", "-c", `cp "$GCP_SA" /tmp/out`}, true},
		{"grep dot file binding", []string{"sh", "-c", `grep . $GCP_SA`}, true},
		{"nohup wrapper", []string{"nohup", "printenv"}, true},
		{"env wrapper to printenv", []string{"env", "FOO=1", "printenv"}, true},
		// command-policy:reader-here-string-reveal-bypass (round 2 review):
		// a reader given no real file operand but a bound Secret's value
		// via a here-string is functionally "cat used as echo" and must be
		// refused the same way a printer given $STRIPE_LIVE already is.
		{"cat here-string reveals bound env var", []string{"sh", "-c", "cat <<< $STRIPE_LIVE"}, true},
		{"tail here-string reveals bound env var", []string{"sh", "-c", "tail <<< $STRIPE_LIVE"}, true},
		{"head here-string reveals bound env var", []string{"sh", "-c", "head <<< $STRIPE_LIVE"}, true},
		{"less here-string reveals bound env var", []string{"sh", "-c", "less <<< $STRIPE_LIVE"}, true},
		// Paired benign: a here-string with nothing dangerous in it stays
		// allowed.
		{"cat here-string with benign text is allowed", []string{"sh", "-c", "cat <<< hello"}, false},
		// command-policy:evaluate-missing-hook-per-word-wrapper-coverage
		// (round 2 review): a reader behind `find -exec`, unrecognized by
		// both the `wrappers` map and the `shells` map, must still be
		// caught — as both a direct argv (no shell) and a shell-string
		// invocation.
		{"find -exec cat dotenv, direct argv", []string{"find", ".", "-exec", "cat", ".env", ";"}, true},
		{"find -exec cat dotenv, shell string", []string{"sh", "-c", `find . -exec cat .env \;`}, true},
		// Paired benign: find with nothing dangerous behind -exec stays
		// allowed, both as direct argv and as a shell string.
		{"find -exec echo hello, direct argv is allowed", []string{"find", ".", "-exec", "echo", "hello", ";"}, false},
		{"find -exec cat unrelated file, shell string is allowed", []string{"sh", "-c", `find . -exec cat /etc/hosts \;`}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: c.argv, Bound: bound})
			if (err != nil) != c.refused {
				t.Fatalf("argv %q: refused=%v want %v (err=%v)", c.argv, err != nil, c.refused, err)
			}
			if err != nil {
				if _, ok := err.(*Refusal); !ok {
					t.Fatalf("want *Refusal, got %T", err)
				}
			}
		})
	}
}

// TestEvaluateDoesNotScanArgv0ForRawLiteral pins CLA-38's raw-literal check
// to arguments only: argv[0] is the program being exec'd, never a value a
// Handle could stand in for, and a real executable path (a build artifact
// under a randomly named temp directory, a versioned tool under a hashed
// store path) routinely reads as high-entropy to the same detector without
// being a Secret — scanning it would make ordinary `cpass run` invocations
// refuse for a reason that has nothing to do with what the command does.
func TestEvaluateDoesNotScanArgv0ForRawLiteral(t *testing.T) {
	argv := []string{"sk_live_51H8xJ2eZvKYlo2CTargvzeroVALUEabc"}
	if err := Evaluate(Input{Argv: argv}); err != nil {
		t.Fatalf("argv[0] must not be scanned for a raw literal: %v", err)
	}
}

func TestProtectedDirs(t *testing.T) {
	in := Input{Bound: bound, ProtectedDirs: []string{"/home/u/.config/claudepass/run"}}
	in.Argv = []string{"cat", "/home/u/.config/claudepass/run/abc/gcp-sa"}
	if Evaluate(in) == nil {
		t.Fatal("literal path under run dir should be refused for a reader")
	}
	in.Argv = []string{"sh", "-c", "head -c 10 /home/u/.config/claudepass/run/abc/gcp-sa"}
	if Evaluate(in) == nil {
		t.Fatal("literal path in shell should be refused")
	}
	// Reopened CLA-61 gap: a run-dir path assigned to a plain variable and
	// referenced with unquoted ${...} braces must resolve back to the
	// literal path the same way the quoted "$VAR" form already does.
	in.Argv = []string{"sh", "-c", "RUNDIR_VAR=/home/u/.config/claudepass/run/abc/gcp-sa; cat ${RUNDIR_VAR}"}
	if Evaluate(in) == nil {
		t.Fatal("literal path via unquoted-braces variable should be refused")
	}
	in.Argv = []string{"gcloud", "--key-file", "/home/u/.config/claudepass/run/abc/gcp-sa"}
	if Evaluate(in) != nil {
		t.Fatal("non-reader may use the path")
	}
	// command-policy:protecteddirs-relative-path-after-cd (round 2 review):
	// a same-command `cd` into the protected run directory followed by a
	// bare relative filename must resolve back to the absolute path
	// underProtected checks against, both for a literal cd target and for
	// one reached through a literal-value variable the same way a
	// file-argument literal already resolves (resolveLiteral).
	in.Argv = []string{"sh", "-c", "cd /home/u/.config/claudepass/run/abc && cat gcp-sa"}
	if Evaluate(in) == nil {
		t.Fatal("relative reference to a live file-Binding after a same-command cd should be refused")
	}
	in.Argv = []string{"sh", "-c", "RUNDIR=/home/u/.config/claudepass/run/abc; cd $RUNDIR && cat gcp-sa"}
	if Evaluate(in) == nil {
		t.Fatal("relative reference after cd via a literal-value variable should be refused")
	}
	// Paired benign: cd-ing somewhere unrelated and reading a relative
	// file there must stay allowed.
	in.Argv = []string{"sh", "-c", "cd /tmp && cat notes.txt"}
	if Evaluate(in) != nil {
		t.Fatal("cd to an unrelated directory must not be refused")
	}
}

// TestProtectedDirsRelativePathAgainstExplicitCwd covers
// command-policy:protecteddirs-relative-path-after-cd's other half: even
// with no `cd` at all, a bare relative reader argument must resolve
// against Input.Cwd — the directory the command will actually run in, as
// the MCP server's run_with_secrets tool supplies it (its own process's
// directory never follows the Agent's, so it cannot rely on os.Getwd()
// alone the way cpass run and EvaluateHook do) — not just against a
// same-command `cd` target.
func TestProtectedDirsRelativePathAgainstExplicitCwd(t *testing.T) {
	in := Input{
		Bound:         bound,
		ProtectedDirs: []string{"/home/u/.config/claudepass/run"},
		Cwd:           "/home/u/.config/claudepass/run/abc",
		Argv:          []string{"cat", "gcp-sa"},
	}
	if Evaluate(in) == nil {
		t.Fatal("a relative reader argument should resolve against the given Cwd and be refused")
	}
	// Paired benign: an unrelated Cwd stays allowed.
	in.Cwd = "/tmp"
	if Evaluate(in) != nil {
		t.Fatal("a relative reader argument under an unrelated Cwd must not be refused")
	}
}

func TestSplitCommands(t *testing.T) {
	cmds := splitCommands(`a "b c" 'd e' f\ g; h | i && j > out 2>&1; k $(l m) n`)
	// CLA-61: a redirection target (here "out") is now captured as a
	// checkable word, same as a bare argument, instead of being dropped.
	want := [][]string{{"a", "b c", "d e", "f g"}, {"h"}, {"i"}, {"j", "out"}, {"k", "$(l m)", "n"}}
	if len(cmds) != len(want) {
		t.Fatalf("got %d commands: %+v", len(cmds), cmds)
	}
	for i := range want {
		if len(cmds[i]) != len(want[i]) {
			t.Fatalf("cmd %d: got %+v want %v", i, cmds[i], want[i])
		}
		for j := range want[i] {
			if cmds[i][j].raw != want[i][j] {
				t.Fatalf("cmd %d word %d: got %q want %q", i, j, cmds[i][j].raw, want[i][j])
			}
		}
	}
	if len(cmds[4][1].subs) != 1 || cmds[4][1].subs[0] != "l m" {
		t.Fatalf("substitution: %+v", cmds[4][1])
	}
}

// TestSplitCommandsUnquotedBraceExpansion is the reopened-CLA-61/CLA-66
// regression: an unquoted ${...} parameter expansion (including ${!x}
// indirect expansion) must tokenize as a single word, not as brace-
// grouping separators around its interior. Before the fix, `cat ${f}`
// mis-split into two simple commands ("cat $" and "f"), so cat never saw
// ${f} as an argument at all and the literal-variable/indirect-expansion
// checks downstream never ran.
func TestSplitCommandsUnquotedBraceExpansion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want [][]string
	}{
		{"plain parameter expansion", `cat ${f}`, [][]string{{"cat", "${f}"}}},
		{"indirect expansion", `echo ${!x}`, [][]string{{"echo", "${!x}"}}},
		{"quoted form still works (regression guard)", `cat "${f}"`, [][]string{{"cat", "${f}"}}},
		// A bare, unrelated `{`/`}` (not immediately after `$`) is still
		// treated as a command-grouping separator, unchanged.
		{"unrelated bare braces still separate", `{ echo hi; }`, [][]string{{"echo", "hi"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmds := splitCommands(c.in)
			if len(cmds) != len(c.want) {
				t.Fatalf("got %d commands: %+v", len(cmds), cmds)
			}
			for i := range c.want {
				if len(cmds[i]) != len(c.want[i]) {
					t.Fatalf("cmd %d: got %+v want %v", i, cmds[i], c.want[i])
				}
				for j := range c.want[i] {
					if cmds[i][j].raw != c.want[i][j] {
						t.Fatalf("cmd %d word %d: got %q want %q", i, j, cmds[i][j].raw, c.want[i][j])
					}
				}
			}
		})
	}
}

// TestShellInvocationFlagsBeforeC is CLA-62's acceptance case #2: Docker's
// own SHELL directive shape, a shell option before -c, must still have its
// -c string evaluated rather than allowed unchecked.
func TestShellInvocationFlagsBeforeC(t *testing.T) {
	cases := []struct {
		name string
		argv []string
	}{
		{"single flag before -c", []string{"bash", "-o", "pipefail", "-c", "cat .env"}},
		{"combined short flags before -c", []string{"bash", "-euo", "pipefail", "-c", "cat .env"}},
		{"plus form before -c", []string{"bash", "+o", "pipefail", "-c", "cat .env"}},
		{"long options before -c", []string{"bash", "--noprofile", "--norc", "-c", "cat .env"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := Evaluate(Input{Argv: c.argv}); err == nil {
				t.Fatalf("argv %q: -c's content must still be checked", c.argv)
			}
		})
	}
}

// TestShellInvocationCombinedOptionOrdering is CLA-62's review fix:
// shellCommandString's combined-short-option branch used to return the word
// immediately after wherever 'c' fell in the group as the -c string, the
// instant it saw the letter — but a real shell (verified live against
// /bin/bash) doesn't read the pending command string until the *entire* run
// of option tokens ends, and o/O each claim the next unclaimed word as they
// are encountered, regardless of which side of 'c' they land on. `-co
// pipefail 'cat .env'` therefore checked "pipefail" as if it were the -c
// string — a string with nothing dangerous in it — and the real command,
// `cat .env`, was never evaluated at all: a full, silent bypass reachable
// with either letter order, either sign.
func TestShellInvocationCombinedOptionOrdering(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"-co: o before the pipefail value, c deferred to the real command", []string{"bash", "-co", "pipefail", "cat .env"}, true},
		{"-oc: o still first in the group, same result", []string{"bash", "-oc", "pipefail", "cat .env"}, true},
		{"+co: plus form, o-then-c ordering", []string{"bash", "+co", "pipefail", "cat .env"}, true},
		{"+oc: plus form, o-then-c ordering, letters swapped", []string{"bash", "+oc", "pipefail", "cat .env"}, true},
		// Paired benign shapes: the exact same combined-option shapes,
		// pointed at a command with nothing dangerous in it, must stay
		// allowed — this is Command Policy correctly checking the real
		// command, not merely refusing every combined-option group on
		// sight.
		{"-co with a safe command is allowed", []string{"bash", "-co", "pipefail", "echo hello"}, false},
		{"-oc with a safe command is allowed", []string{"bash", "-oc", "pipefail", "echo hello"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: c.argv})
			if (err != nil) != c.refused {
				t.Fatalf("argv %q: refused=%v want %v (err=%v)", c.argv, err != nil, c.refused, err)
			}
		})
	}
}

// TestShellInvocationUnrecognizedShapeRefuses is CLA-62's fail-closed
// default: a shell-invocation shape shellCommandString cannot resolve to
// concrete content must be refused, never silently allowed.
func TestShellInvocationUnrecognizedShapeRefuses(t *testing.T) {
	cases := []struct {
		name string
		argv []string
	}{
		{"bare shell, nothing to check", []string{"sh"}},
		{"-s, reading real stdin, not statically visible", []string{"sh", "-s"}},
		{"unrecognised long option", []string{"bash", "--rcfile", "x", "-c", "true"}},
		{"-c with no value", []string{"sh", "-c"}},
		{"-o with no value", []string{"bash", "-o"}},
		{"nonexistent script path", []string{"bash", "/does/not/exist/script.sh"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := Evaluate(Input{Argv: c.argv}); err == nil {
				t.Fatalf("argv %q: an unresolvable shell-invocation shape must refuse (fail closed)", c.argv)
			}
		})
	}
}

// TestShellInvocationScriptByPath is CLA-62's acceptance case #1: a bare
// `<shell> script.sh` must have the script's own content statically
// evaluated exactly like an inline -c string — this is what keeps `cpass
// run -- bash script.sh` working for a legitimate script, not just refusing
// every script-by-path invocation outright.
func TestShellInvocationScriptByPath(t *testing.T) {
	dir := t.TempDir()
	dangerous := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(dangerous, []byte("#!/bin/sh\ncat .env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(dir, "safe.sh")
	if err := os.WriteFile(safe, []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Evaluate(Input{Argv: []string{"bash", dangerous}}); err == nil {
		t.Fatalf("a script reading .env must be refused: %s", dangerous)
	}
	if err := Evaluate(Input{Argv: []string{"bash", safe}}); err != nil {
		t.Fatalf("a script that does nothing dangerous must still run: %v", err)
	}
	// A script larger than maxStaticScriptSize can't be statically
	// checked, so it must refuse rather than run unchecked.
	big := filepath.Join(dir, "big.sh")
	huge := make([]byte, maxStaticScriptSize+1)
	for i := range huge {
		huge[i] = 'x'
	}
	if err := os.WriteFile(big, huge, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Evaluate(Input{Argv: []string{"bash", big}}); err == nil {
		t.Fatalf("an oversized script must refuse rather than run unchecked")
	}
}

// TestShellInvocationHeredoc covers CLA-64's third false-positive class
// from the shell-invocation side: a heredoc body attached to a shell must
// still be evaluated (regardless of whether its delimiter is quoted),
// while one attached to any other program is never scanned as commands —
// it is data streamed to that program's stdin.
func TestShellInvocationHeredoc(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"quoted delimiter to a shell", []string{"sh", "-c", "sh <<'EOF'\ncat .env\nEOF\n"}, true},
		{"unquoted delimiter to a shell", []string{"sh", "-c", "bash <<EOF\ncat .env\nEOF\n"}, true},
		{"quoted delimiter to a non-shell interpreter", []string{"sh", "-c", "python3 - <<'EOF'\ncat .env\nEOF\n"}, false},
		// CLA-62 review: a -c STRING is what a real shell actually runs
		// even when a heredoc is attached alongside it — the heredoc is
		// just stdin data for that invocation, not a decoy that can hide
		// a dangerous -c string behind a benign-looking body. Before this
		// fix the heredoc was checked first and, when present, evaluated
		// instead of -c's own content, a full silent bypass.
		{"dangerous -c string alongside a benign heredoc is still refused", []string{"sh", "-c", "bash -c \"cat .env\" <<'EOF'\necho decoy\nEOF\n"}, true},
		// The converse also matches real shell semantics: a safe -c
		// string is unaffected by a heredoc that merely looks dangerous,
		// since that heredoc is never executed as commands.
		{"safe -c string alongside a heredoc that merely looks dangerous is allowed", []string{"sh", "-c", "bash -c 'echo hi' <<'EOF'\ncat .env\nEOF\n"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: c.argv})
			if (err != nil) != c.refused {
				t.Fatalf("argv %v: refused=%v want %v (err=%v)", c.argv, err != nil, c.refused, err)
			}
		})
	}
}

// TestSplitCommandsUnquotedHeredocSubs is CLA-61's review-fix regression at
// the tokenizer level: an UNQUOTED heredoc delimiter's body is expanded by a
// real shell — command substitutions and backticks included — before it
// ever reaches the reading program's stdin, so splitCommands must populate
// the heredoc word's own subs exactly like it already does for a
// double-quoted string. A QUOTED delimiter's body stays genuinely inert:
// no subs, ever, regardless of what its text looks like.
func TestSplitCommandsUnquotedHeredocSubs(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantSubs   []string
		wantQuoted bool
	}{
		{"unquoted delimiter, command substitution", "cat <<EOF\n$(cat .env)\nEOF\n", []string{"cat .env"}, false},
		{"unquoted delimiter, backtick substitution", "cat <<EOF\n`cat .env`\nEOF\n", []string{"cat .env"}, false},
		{"unquoted delimiter, no substitution at all", "cat <<EOF\nhello world\nEOF\n", nil, false},
		{"quoted delimiter, would-be substitution stays inert", "cat <<'EOF'\n$(cat .env)\nEOF\n", nil, true},
		{"double-quoted delimiter, would-be substitution stays inert", "cat <<\"EOF\"\n$(cat .env)\nEOF\n", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmds := splitCommands(c.in)
			if len(cmds) != 1 || len(cmds[0]) != 2 {
				t.Fatalf("got %+v", cmds)
			}
			hd := cmds[0][1]
			if !hd.hasHeredoc {
				t.Fatalf("word 1 should be the heredoc body: %+v", hd)
			}
			if hd.heredocQuoted != c.wantQuoted {
				t.Fatalf("heredocQuoted = %v, want %v", hd.heredocQuoted, c.wantQuoted)
			}
			if len(hd.subs) != len(c.wantSubs) {
				t.Fatalf("subs = %+v, want %+v", hd.subs, c.wantSubs)
			}
			for i := range c.wantSubs {
				if hd.subs[i] != c.wantSubs[i] {
					t.Fatalf("subs[%d] = %q, want %q", i, hd.subs[i], c.wantSubs[i])
				}
			}
		})
	}
}

// TestShellInvocationHeredocUnquotedExpansionAnyProgram is CLA-61's
// review-fix regression at the Evaluate level: a real shell expands an
// UNQUOTED heredoc delimiter's body — command substitutions and parameter
// expansions alike — before it ever reaches the reading program's stdin, so
// this must be caught regardless of which program the heredoc is attached
// to, not only a shell (whose own attached heredoc is already fully
// re-parsed as a script by the shells[prog] case, quoted or not). Before
// this fix, splitCommands stored a heredoc's body as opaque text and never
// populated its subs, so a $(...) or backtick buried in an UNQUOTED body was
// invisible to Command Policy for every program except a shell.
func TestShellInvocationHeredocUnquotedExpansionAnyProgram(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		bound   []Var
		refused bool
	}{
		{"unquoted heredoc's $(...) reads .env, attached to cat", []string{"sh", "-c", "cat <<EOF\n$(cat .env)\nEOF\n"}, nil, true},
		{"unquoted heredoc's backtick sub reads .env, attached to cat", []string{"sh", "-c", "cat <<EOF\n`cat .env`\nEOF\n"}, nil, true},
		// The same substitution, attached to a program that isn't on the
		// readers list at all — the fix walks every word's subs
		// unconditionally, the same way command substitutions elsewhere
		// in an argument are already evaluated regardless of which
		// program they sit next to.
		{"unquoted heredoc's $(...) reads .env, attached to a non-reader program", []string{"sh", "-c", "wc -l <<EOF\n$(cat .env)\nEOF\n"}, nil, true},
		// Paired benign: the quoted-delimiter counterpart of the exact
		// same body is genuinely inert data in a real shell — .env is
		// never read, the literal text "$(cat .env)" is all that's ever
		// printed.
		{"quoted heredoc's would-be substitution stays inert", []string{"sh", "-c", "cat <<'EOF'\n$(cat .env)\nEOF\n"}, nil, false},
		// A reveal-only bound variable reference in an unquoted heredoc
		// body resolves to the Secret's real value before the reading
		// program (given no file operand) ever starts — exactly like
		// `echo $STRIPE_LIVE`.
		{"unquoted heredoc reveals a bound variable", []string{"sh", "-c", "cat <<EOF\n$STRIPE_LIVE\nEOF\n"}, bound, true},
		// Paired benign: the quoted-delimiter counterpart never expands
		// $STRIPE_LIVE at all — cat just prints the four literal
		// characters, never the Secret's value.
		{"quoted heredoc naming a bound variable as literal text stays inert", []string{"sh", "-c", "cat <<'EOF'\n$STRIPE_LIVE\nEOF\n"}, bound, false},
		// Paired benign: an unquoted heredoc with nothing dangerous in it
		// at all must stay allowed.
		{"unquoted heredoc with benign text is allowed", []string{"sh", "-c", "cat <<EOF\nhello world\nEOF\n"}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: c.argv, Bound: c.bound})
			if (err != nil) != c.refused {
				t.Fatalf("argv %v: refused=%v want %v (err=%v)", c.argv, err != nil, c.refused, err)
			}
		})
	}
}

// TestShellInvocationScriptByPathWithHeredoc is CLA-62's review fix: a
// script-by-path argument is what a real shell actually runs even when a
// heredoc is attached alongside it, exactly like the -c STRING case in
// TestShellInvocationHeredoc above — the heredoc must not be able to hide
// a dangerous script behind a benign-looking body.
func TestShellInvocationScriptByPathWithHeredoc(t *testing.T) {
	dir := t.TempDir()
	dangerous := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(dangerous, []byte("#!/bin/sh\ncat .env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	argv := []string{"sh", "-c", "bash " + dangerous + " <<'EOF'\necho decoy\nEOF\n"}
	if err := Evaluate(Input{Argv: argv}); err == nil {
		t.Fatalf("a dangerous script paired with a benign heredoc must still be refused: %v", argv)
	}
}

// TestControlFlowKeywordCommandPosition is
// command-policy:control-flow-keyword-bypass (round 2 review): a shell
// reserved word (if/then/elif/else/fi/while/until/do/done/for/in) is never
// a real program name, so `if cat .env; then true; fi` must still evaluate
// `cat .env` as a real simple command, the same way `sh -c 'cat .env'`
// already does — before this fix splitCommands never recognized these
// words at all, so the whole line tokenized as one bogus simple command
// with prog=="if", and the real `cat .env` invocation was never separately
// checked.
func TestControlFlowKeywordCommandPosition(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"if condition reads a secret file", []string{"sh", "-c", "if cat .env; then true; fi"}, true},
		{"while condition reads a secret file", []string{"sh", "-c", "while cat .env; do break; done"}, true},
		{"until condition reads a secret file", []string{"sh", "-c", "until cat .env; do break; done"}, true},
		// The reveal variant: Command Policy's own "refuses ... reveal a
		// Secret" promise, not merely Redaction downstream, must hold for
		// a bound variable printed from inside a control-flow body too.
		{"if body reveals a bound variable", []string{"sh", "-c", "if true; then echo $STRIPE_LIVE; fi"}, true},
		{"while body reveals a bound variable", []string{"sh", "-c", "while true; do echo $STRIPE_LIVE; break; done"}, true},
		// Paired benign shapes: an ordinary if/while/for construct with
		// nothing dangerous in it must stay allowed — this is Command
		// Policy correctly judging the real commands inside, not merely
		// refusing every control-flow construct on sight.
		{"if condition and body are both benign", []string{"sh", "-c", "if true; then echo hello; fi"}, false},
		{"while loop is benign", []string{"sh", "-c", "while false; do echo hello; done"}, false},
		{"for loop over a literal list is benign", []string{"sh", "-c", "for i in 1 2 3; do echo $i; done"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: c.argv, Bound: bound})
			if (err != nil) != c.refused {
				t.Fatalf("argv %v: refused=%v want %v (err=%v)", c.argv, err != nil, c.refused, err)
			}
		})
	}
}

// TestSplitCommandsControlFlowKeywords is the tokenizer-level regression
// for TestControlFlowKeywordCommandPosition above: a reserved word in
// command-start position is discarded so the following word starts a
// fresh simple command, while the exact same text used as an ordinary
// argument (not a command's own first word) is left alone.
func TestSplitCommandsControlFlowKeywords(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want [][]string
	}{
		{"if/then/fi around a condition and body", "if cat .env; then true; fi",
			[][]string{{"cat", ".env"}, {"true"}}},
		{"while/do/done", "while cat .env; do break; done",
			[][]string{{"cat", ".env"}, {"break"}}},
		{"until/do/done", "until cat .env; do break; done",
			[][]string{{"cat", ".env"}, {"break"}}},
		{"a reserved word used as data (not command-start) is untouched", "echo if then fi",
			[][]string{{"echo", "if", "then", "fi"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmds := splitCommands(c.in)
			if len(cmds) != len(c.want) {
				t.Fatalf("got %d commands: %+v", len(cmds), cmds)
			}
			for i := range c.want {
				if len(cmds[i]) != len(c.want[i]) {
					t.Fatalf("cmd %d: got %+v want %v", i, cmds[i], c.want[i])
				}
				for j := range c.want[i] {
					if cmds[i][j].raw != c.want[i][j] {
						t.Fatalf("cmd %d word %d: got %q want %q", i, j, cmds[i][j].raw, c.want[i][j])
					}
				}
			}
		})
	}
}

// TestAnsiCAndLocaleQuoting is
// command-policy:quoting-ansi-c-and-locale-strings (round 2 review):
// splitCommands had no case for $'...' (ANSI-C) or $"..." (locale)
// quoting, so both fell through to the default handler, which wrote a
// literal '$' and then parsed '...'/"..." as an ordinary quoted string —
// mangling `cat $'.env'` into the word "$.env", which matches no
// secret-file glob at all.
func TestAnsiCAndLocaleQuoting(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"ANSI-C quoting as the sole argument", []string{"sh", "-c", `cat $'.env'`}, true},
		{"locale quoting as the sole argument", []string{"sh", "-c", `cat $".env"`}, true},
		{"ANSI-C quoting with a real escape still resolves to .env", []string{"sh", "-c", `cat $'.e\x6ev'`}, true},
		// Glued to a prefix, ANSI-C quoting still merges into one word
		// with the surrounding text (no literal '$' left behind), but the
		// resulting basename ("a.env") doesn't match any secret-file glob
		// (those require the basename to itself start with ".env"), so
		// this must stay allowed — not refused for the wrong reason.
		{"ANSI-C quoting glued to a prefix does not create a secret filename", []string{"sh", "-c", `cat a$'.env'`}, false},
		// Paired benign: the same quoting forms around ordinary,
		// non-secret text must stay allowed.
		{"ANSI-C quoting around benign text is allowed", []string{"sh", "-c", `cat $'hello'`}, false},
		{"locale quoting around benign text is allowed", []string{"sh", "-c", `cat $"hello"`}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: c.argv, Bound: bound})
			if (err != nil) != c.refused {
				t.Fatalf("argv %v: refused=%v want %v (err=%v)", c.argv, err != nil, c.refused, err)
			}
		})
	}
}

// TestSplitCommandsAnsiCAndLocaleQuoting is the tokenizer-level regression:
// $'...' consumes no literal leading '$', applies backslash-escape
// processing, and $"..." behaves exactly like an ordinary double-quoted
// string (also consuming no literal leading '$').
func TestSplitCommandsAnsiCAndLocaleQuoting(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ANSI-C quoting, no escapes", `cat $'.env'`, ".env"},
		{"locale quoting, no escapes", `cat $".env"`, ".env"},
		{"ANSI-C quoting, hex escape", `cat $'.e\x6ev'`, ".env"},
		{"ANSI-C quoting, octal escape", `cat $'.e\156v'`, ".env"},
		{"ANSI-C quoting, common escapes", `echo $'a\tb\nc'`, "a\tb\nc"},
		{"ANSI-C quoting, unrecognized escape drops only the backslash", `echo $'a\qb'`, "aqb"},
		{"locale quoting embeds a command substitution like a normal double-quoted string", `echo $"pre$(cat .env)post"`, "pre$(cat .env)post"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmds := splitCommands(c.in)
			if len(cmds) != 1 || len(cmds[0]) != 2 {
				t.Fatalf("got %+v", cmds)
			}
			if got := cmds[0][1].raw; got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

// TestBraceExpansion is command-policy:brace-expansion-hides-filename
// (round 2 review): bash brace expansion ({a,b}) was not implemented at
// all, and a bare `{`/`}` was unconditionally treated as a command-
// grouping separator even when glued to adjacent text, so `cat
// .{env,bashrc}` mis-tokenized into fragments that never presented ".env"
// as a checkable argument to cat at all.
func TestBraceExpansion(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"comma list expands to a secret-file basename", []string{"sh", "-c", "cat .{env,bashrc}"}, true},
		{"comma list, secret file listed second", []string{"sh", "-c", "cat .{bashrc,env}"}, true},
		{"numeric range expands to a secret-file basename", []string{"sh", "-c", "cat id_rsa{1..2}"}, true},
		// Paired benign: brace expansion around nothing dangerous stays
		// allowed.
		{"comma list with nothing dangerous is allowed", []string{"sh", "-c", "echo .{txt,md}"}, false},
		{"standalone braces still group commands, unchanged", []string{"sh", "-c", "{ echo hi; }"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: c.argv, Bound: bound})
			if (err != nil) != c.refused {
				t.Fatalf("argv %v: refused=%v want %v (err=%v)", c.argv, err != nil, c.refused, err)
			}
		})
	}
}

// TestSplitCommandsBraceExpansion is the tokenizer-level regression: a
// glued {a,b,c}/{n..m}/{a..z} span expands into the separate words it
// stands for, exactly like a real shell's own brace expansion, while a
// standalone `{`/`}` token still separates commands unchanged and a
// glued-but-unrecognized span (no comma, no "..") is left as intact
// literal text rather than being truncated.
func TestSplitCommandsBraceExpansion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"comma list", "cat .{env,bashrc}", []string{"cat", ".env", ".bashrc"}},
		{"comma list, three alternatives", "echo {a,b,c}", []string{"echo", "a", "b", "c"}},
		{"numeric range", "echo file{1..3}.txt", []string{"echo", "file1.txt", "file2.txt", "file3.txt"}},
		{"descending numeric range", "echo {3..1}", []string{"echo", "3", "2", "1"}},
		{"letter range", "echo {a..c}", []string{"echo", "a", "b", "c"}},
		{"unrecognized span (no comma, no range) is left intact", "echo {notaspan}", []string{"echo", "{notaspan}"}},
		{"nested braces are left intact (not attempted)", "echo {a,{b,c}}", []string{"echo", "{a,{b,c}}"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmds := splitCommands(c.in)
			if len(cmds) != 1 {
				t.Fatalf("got %d commands: %+v", len(cmds), cmds)
			}
			if len(cmds[0]) != len(c.want) {
				t.Fatalf("got %+v want %v", cmds[0], c.want)
			}
			for i := range c.want {
				if cmds[0][i].raw != c.want[i] {
					t.Fatalf("word %d: got %q want %q", i, cmds[0][i].raw, c.want[i])
				}
			}
		})
	}
}

// TestDynamicCommandNameLiteralVariable is
// command-policy:dynamic-command-name-not-resolved (round 2 review): when
// a simple command's first word is a whole variable reference ($x/${x})
// to a plain-string literal already tracked in ev.literals, a real shell
// expands and re-parses that literal as the actual command line — `x='cat
// .env'; $x` really executes `cat .env` — so Evaluate must re-split and
// re-evaluate it the same way eval's argument already is.
func TestDynamicCommandNameLiteralVariable(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"$x names a literal command reading a secret file", []string{"sh", "-c", `x='cat .env'; $x`}, true},
		{"${x} form, same literal command", []string{"sh", "-c", `x='cat .env'; ${x}`}, true},
		{"$x with an extra trailing argument appended after word-splitting", []string{"sh", "-c", `x=cat; $x .env`}, true},
		// Paired benign: a literal command with nothing dangerous in it
		// stays allowed.
		{"$x names a literal, benign command", []string{"sh", "-c", `x='echo hello'; $x`}, false},
		// Paired benign: a variable NOT tracked as a plain-string literal
		// (assigned from a bound Secret, not a literal) must not be
		// treated as a resolvable command name by this mechanism — it
		// falls through to ordinary (unrefused, since running a Secret's
		// value as a program name doesn't itself print anything) argv
		// dispatch, unchanged from before this fix.
		{"an unset/unknown variable as command name is left alone", []string{"sh", "-c", `$UNKNOWN_CMD .env`}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: c.argv, Bound: bound})
			if (err != nil) != c.refused {
				t.Fatalf("argv %v: refused=%v want %v (err=%v)", c.argv, err != nil, c.refused, err)
			}
		})
	}
}
