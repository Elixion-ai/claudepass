package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/broker"
)

func TestEvaluateHook(t *testing.T) {
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		// allowed
		{"plain command", "ls", false},
		{"plain command with args", "ls -la /tmp", false},
		{"unrelated file read", "cat /etc/hosts", false},
		{"grep unrelated file", "grep foo bar.txt", false},
		{"cpass run wrapping a safe command", "cpass run --with stripe/live -- curl -H \"Authorization: Bearer $STRIPE_LIVE\" https://x", false},
		{"cpass add handle only", "cpass add stripe/live", false},
		{"cpass add with a binding flag but no value", "cpass add stripe/live --binding STRIPE_KEY", false},
		{"the global short flag is not an inline value", "cpass add stripe/live -g", false},
		{"the global long flag is not an inline value", "cpass add stripe/live --global", false},
		{"global flag alongside a binding", "cpass add stripe/live -g --binding STRIPE_KEY", false},
		{"cpass ls", "cpass ls", false},
		{"cpass manifest check", "cpass manifest check", false},
		{"echo plain text", "echo hello", false},
		{"cpass run wrapping env is not pre-blocked by the hook", "cpass run -- env", false},
		// CLA-65: a public key or a template dotenv is not a Secret.
		{"cat id_rsa pub is not a secret", "cat id_rsa.pub", false},
		{"cat dotenv example is not a secret", "cat .env.example", false},
		{"quoted heredoc body fed to a non-shell interpreter is data", "python3 - <<'EOF'\ncat .env\nEOF\n", false},
		// CLA-62 review: the converse of the refused case below — a safe
		// -c string is unaffected by a heredoc that merely looks
		// dangerous, since that heredoc is never executed as commands.
		{"safe -c string alongside a heredoc that merely looks dangerous is allowed", "bash -c 'echo hi' <<'EOF'\ncat .env\nEOF\n", false},
		// CLA-64: a reader named as data (not as argv[0] of its own
		// command) must not be mistaken for one actually running — the
		// three false-positive classes this ticket fixes surgically.
		{"echo mentioning cat as data", "echo cat .env", false},
		{"printf mentioning cat as data", `printf 'cat .env'`, false},
		{"find's own . argument is not the source builtin", `find . -name "*.key"`, false},
		// CLA-64 review: the printer exemption above must skip past a
		// leading VAR=value assignment before checking the command word,
		// not just look at word 0 literally.
		{"leading assignment before echo still exempts its data argument", "DEBUG=1 echo cat .env", false},

		// refused: secret-bearing file reads
		{"cat dotenv", "cat .env", true},
		{"cat dotenv variant", "cat .env.production", true},
		{"cat dotenv via home var", "cat $HOME/.env", true},
		{"less pem file", "less server.pem", true},
		{"head id_rsa", "head id_rsa", true},
		{"cat star key", "cat stripe.key", true},
		{"cat credentials json", "cat credentials.json", true},
		{"cat netrc", "cat .netrc", true},
		{"cat npmrc", "cat .npmrc", true},
		{"source dotenv", "source .env", true},
		{"dot source dotenv", ". .env", true},
		{"reader with flag before file", "cat -A .env", true},
		{"reader inside pipeline", "cat .env | base64", true},
		{"reader inside nested shell", `sh -c "cat .env"`, true},
		{"reader wrapped by cpass run", "cpass run -- cat .env", true},
		{"reader in command substitution", "echo $(cat .env)", true},
		// CLA-61: redirection target, literal-value variable, and a real
		// backslash-newline continuation are all just as reachable a
		// bypass as a direct `cat .env`.
		{"cat dotenv via input redirection", "cat < .env", true},
		{"cat dotenv via literal-value variable", `f=.env; cat "$f"`, true},
		{"cat dotenv via backslash-newline continuation", "ca\\\nt .env", true},
		// Reopened CLA-61 gap: the unquoted ${f} spelling was tokenized as
		// brace-grouping separators, so it silently bypassed the same
		// literal-variable check the quoted "$f" case above already
		// covered.
		{"cat dotenv via unquoted-braces literal variable", `f=.env; cat ${f}`, true},
		// CLA-64: the wrapper patterns the per-word scan must keep
		// catching, unnarrowed by the false-positive fixes above.
		{"find -exec cat .env still refused", `find . -exec cat .env \;`, true},
		{"timeout wrapping cat .env still refused", "timeout 5 cat .env", true},
		{"nice wrapping cat .env still refused", "nice cat .env", true},
		{"xargs cat via redirect still refused", "xargs cat < .env", true},
		{"sudo cat .env still refused", "sudo cat .env", true},
		{"echo piped into a bare shell still refused", "echo cat .env | sh", true},
		// CLA-64: a heredoc attached to a shell is still evaluated as the
		// script it is, whether or not its delimiter is quoted.
		{"quoted heredoc body fed to a shell", "sh <<'EOF'\ncat .env\nEOF\n", true},
		{"unquoted heredoc body fed to a shell", "bash <<EOF\ncat .env\nEOF\n", true},
		// CLA-62 review: a -c STRING is what actually executes even when
		// a heredoc is attached alongside it — the heredoc is just stdin
		// data for that invocation, not a decoy that can hide a
		// dangerous -c string behind a benign-looking body. Before this
		// fix the heredoc was checked first and, when present, evaluated
		// instead of -c's own content: a full, silent bypass.
		{"dangerous -c string alongside a benign heredoc is still refused", "bash -c \"cat .env\" <<'EOF'\necho decoy\nEOF\n", true},
		// CLA-61 review: an UNQUOTED heredoc delimiter's body is expanded
		// by a real shell — command substitutions included — before it
		// ever reaches the reading program's stdin, regardless of which
		// program that is; a QUOTED delimiter's body stays genuinely
		// inert. Split from the shell case above since these are
		// attached to `cat`/`wc`, not a shell.
		{"unquoted heredoc's command substitution reads .env, attached to cat", "cat <<EOF\n$(cat .env)\nEOF\n", true},
		{"unquoted heredoc's backtick substitution reads .env, attached to cat", "cat <<EOF\n`cat .env`\nEOF\n", true},
		{"unquoted heredoc's command substitution reads .env, attached to a non-reader program", "wc -l <<EOF\n$(cat .env)\nEOF\n", true},
		{"quoted heredoc's would-be command substitution stays inert", "cat <<'EOF'\n$(cat .env)\nEOF\n", false},
		{"unquoted heredoc with benign text is allowed", "cat <<EOF\nhello world\nEOF\n", false},

		// CLA-62 review: shellCommandString's combined-short-option
		// branch used to return the word right after wherever 'c' fell
		// in the group as the -c string the instant it saw the letter —
		// but a real shell doesn't read the pending command string until
		// the whole run of option tokens ends, and o/O each claim the
		// next unclaimed word wherever they fall. `-co pipefail 'cat
		// .env'` therefore checked "pipefail", never the real command.
		{"combined -co: o's value first, c's string is the real command", "bash -co pipefail 'cat .env'", true},
		{"combined -oc: same result with the letters swapped", "bash -oc pipefail 'cat .env'", true},
		{"combined -co with a safe command is allowed", "bash -co pipefail 'echo hello'", false},

		// refused: raw Secret-shaped literal
		{"stripe key literal in curl", `curl -H "Authorization: Bearer sk_live_51H8xJ2eZvKYlo2CTvalueabcdefgh"`, true},
		{"github token literal", "export GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz99", true},

		// refused: cpass add given an inline value
		{"cpass add with inline value", "cpass add stripe/live sk_live_51H8xJ2eZvKYlo2CTvalueabcdefgh", true},
		{"cpass add with inline value after flags", "cpass add stripe/live --file inbox-secret-value-right-here", true},

		// refused: ordinary Command Policy rules, only when not wrapped
		{"bare env", "env", true},
		{"bare printenv", "printenv", true},
		{"bare set", "set", true},
		{"export dash p", "export -p", true},
		{"proc self environ", "cat /proc/self/environ", true},

		// round 2 review: command-policy:control-flow-keyword-bypass — a
		// shell reserved word in command-start position is never a real
		// program name; the real command inside must still be checked.
		// (The reveal variant — a bound variable printed from an if/while
		// body — has no Bound value at this Bound-independent hook layer
		// to check against at all; it is covered at the Evaluate layer,
		// where a Handle is actually bound, by
		// TestControlFlowKeywordCommandPosition and this ticket's e2e
		// case below.)
		{"if condition reads a secret file", "if cat .env; then true; fi", true},
		{"while condition reads a secret file", "while cat .env; do break; done", true},
		{"until condition reads a secret file", "until cat .env; do break; done", true},
		{"if/then/fi with nothing dangerous is allowed", "if true; then echo hello; fi", false},
		{"for loop over a literal list is allowed", "for i in 1 2 3; do echo $i; done", false},

		// round 2 review: command-policy:quoting-ansi-c-and-locale-strings
		{"ANSI-C quoting names a secret file", `cat $'.env'`, true},
		{"locale quoting names a secret file", `cat $".env"`, true},
		{"ANSI-C quoting around benign text is allowed", `cat $'hello'`, false},

		// round 2 review: command-policy:brace-expansion-hides-filename
		{"brace expansion names a secret file", "cat .{env,bashrc}", true},
		{"brace expansion with nothing dangerous is allowed", "echo .{txt,md}", false},

		// round 2 review: command-policy:dynamic-command-name-not-resolved
		{"a whole variable naming a literal command reading a secret file", `x='cat .env'; $x`, true},
		{"a whole variable naming a literal, benign command is allowed", `x='echo hello'; $x`, false},

		// round 2 review:
		// command-policy:evaluate-missing-hook-per-word-wrapper-coverage —
		// already caught by hookWalk's own per-word scan before this
		// round, kept here so the hook-level table stays a complete,
		// standalone record of every shape this ticket batch closes.
		{"find -exec cat dotenv still refused at the hook layer", `find . -exec cat .env \;`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := EvaluateHook(c.command)
			if (err != nil) != c.refused {
				t.Fatalf("command %q: refused=%v want %v (err=%v)", c.command, err != nil, c.refused, err)
			}
			if err != nil {
				if _, ok := err.(*Refusal); !ok {
					t.Fatalf("want *Refusal, got %T", err)
				}
			}
		})
	}
}

func TestEvaluateHookEmptyCommand(t *testing.T) {
	if err := EvaluateHook(""); err != nil {
		t.Fatalf("empty command should be allowed: %v", err)
	}
	if err := EvaluateHook("   "); err != nil {
		t.Fatalf("blank command should be allowed: %v", err)
	}
}

func TestEvaluateHookDoesNotLeakDetectedValueInRefusal(t *testing.T) {
	secret := "sk_live_51H8xJ2eZvKYlo2CTvalueabcdefgh"
	err := EvaluateHook("curl -H \"Authorization: Bearer " + secret + "\"")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("refusal message must not repeat the Secret value: %v", err)
	}
}

// TestEvaluateHookProtectedDirs is CLA-63's acceptance case: the hook must
// refuse a raw Bash call that cats a live file-Binding's run-directory path
// by literal path, matching policy_test.go's TestProtectedDirs coverage of
// the non-hook path — EvaluateHook never wired ProtectedDirs in at all
// before this fix, so this refused unconditionally on the old code.
func TestEvaluateHookProtectedDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv(broker.EnvHome, home)
	target := filepath.Join(home, "run", "abc123", "gcp-sa")
	if err := EvaluateHook("cat " + target); err == nil {
		t.Fatalf("cat on a path under the run dir root should be refused: %s", target)
	}
	if err := EvaluateHook(`sh -c "head -c 10 ` + target + `"`); err == nil {
		t.Fatalf("the same path inside a nested shell should be refused: %s", target)
	}
	// Reopened CLA-61 gap: the same path assigned to a plain variable and
	// referenced with unquoted ${...} braces must resolve back to the
	// literal path too, not just a bare literal argument.
	if err := EvaluateHook("RUNDIR_VAR=" + target + "; cat ${RUNDIR_VAR}"); err == nil {
		t.Fatalf("the same path via an unquoted-braces variable should be refused: %s", target)
	}
	// An unrelated path outside the run dir root is unaffected.
	if err := EvaluateHook("cat " + filepath.Join(home, "vault.cpv")); err != nil {
		t.Fatalf("a path outside the run dir root must not be refused: %v", err)
	}
	// command-policy:protecteddirs-relative-path-after-cd (round 2
	// review): a same-command `cd` into the run directory followed by a
	// bare relative filename must resolve back to the absolute path
	// underProtected checks against.
	targetDir := filepath.Join(home, "run", "abc123")
	if err := EvaluateHook("cd " + targetDir + " && cat gcp-sa"); err == nil {
		t.Fatalf("a relative reference after a same-command cd into the run dir should be refused: %s", targetDir)
	}
	// Paired benign: cd-ing somewhere unrelated stays allowed.
	if err := EvaluateHook("cd " + t.TempDir() + " && cat notes.txt"); err != nil {
		t.Fatalf("cd to an unrelated directory must not be refused: %v", err)
	}
}

// TestEvaluateHookShellInvocationShapes is CLA-62's acceptance at the hook
// layer: a shell option before -c, and a script-by-path invocation, must
// both still have their content evaluated instead of passing through
// unchecked, and an unresolvable shape must refuse (fail closed).
func TestEvaluateHookShellInvocationShapes(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat .env\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(dir, "safe.sh")
	if err := os.WriteFile(safe, []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"flag before -c still evaluates -c's content", `bash -o pipefail -c 'cat .env'`, true},
		{"script-by-path reading .env is refused", "bash " + script, true},
		{"script-by-path doing nothing dangerous still runs", "bash " + safe, false},
		{"unrecognised shell-invocation shape fails closed", "bash --rcfile x -c true", true},
		// CLA-62 review: a script-by-path argument is what actually
		// executes even when a heredoc is attached alongside it.
		{"script-by-path reading .env alongside a benign heredoc is still refused", "bash " + script + " <<'EOF'\necho decoy\nEOF\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := EvaluateHook(c.command)
			if (err != nil) != c.refused {
				t.Fatalf("command %q: refused=%v want %v (err=%v)", c.command, err != nil, c.refused, err)
			}
		})
	}
}
