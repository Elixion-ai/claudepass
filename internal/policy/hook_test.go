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
		// 2026-09-23 audit false-positive A/B corpus
		// (command-policy:shell-behind-wrapper-heredoc-lost-on-argv-
		// conversion): a shell name behind an unenumerated wrapper
		// (ssh/docker) that receives its script only via an attached
		// heredoc, not -c/a script path, must still resolve that
		// heredoc's body as the executed script the same way a bare `sh
		// <<EOF` already does — losing the heredoc on the way to a
		// plain-string argv previously made this look like an
		// unparseable bare-shell invocation.
		{"ssh piping a heredoc script into bash is allowed", "ssh build-host bash <<'EOF'\ncd /srv/app\ngit pull\nmake build\nEOF\n", false},
		{"paired bypass: the same ssh shape reading a secret file in its heredoc body is still refused", "ssh build-host bash <<'EOF'\ncat .env\nEOF\n", true},
		{"docker run piping a heredoc script into sh is allowed", "docker run --rm -i alpine sh <<'EOF'\necho hello from container\nuname -a\nEOF\n", false},
		{"paired bypass: the same docker shape reading a secret file in its heredoc body is still refused", "docker run --rm -i alpine sh <<'EOF'\ncat .env\nEOF\n", true},
		// command-policy:shell-script-path-literal-variable: a script
		// path stashed in a shell variable (`G=script.sh; bash $G`) must
		// resolve back to the real, checkable file the same way the
		// literal spelling `bash script.sh` already does.
		{"a script path held in a shell variable resolves to the safe script", "G=" + safe + "; bash $G", false},
		{"paired bypass: a script path held in a shell variable resolves to the dangerous script", "G=" + script + "; bash $G", true},
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

// TestEvaluateHookReaderPatternArgumentNotAFilename is
// command-policy:reader-pattern-argument-not-a-filename and
// command-policy:glob-pattern-vs-reader-filter-argument (2026-09-23
// audit's false-positive A/B corpus): grep/sed/awk/jq/yq's own regex,
// substitution script, program, or filter argument is routinely
// shaped like a filename glob (brackets, a leading dot after
// de-escaping, ...) or happens to spell a secretFileGlobs pattern
// outright, but it is never the file being read — the real file
// argument, when there is one, is a later positional.
func TestEvaluateHookReaderPatternArgumentNotAFilename(t *testing.T) {
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"jq's own filter expression is not a filename glob", `jq -r '.[] | .name' data.json`, false},
		{"grep -E pattern with a bracket expression is not a filename glob", `/usr/bin/grep -E "^\s+[a-z-]+ " somefile.txt`, false},
		{"sed substitution script is not a filename glob", `sed -E 's/^[^ ]+ - - \[([^]]+)\].*/\1/' access.log`, false},
		{"grep -l with an id_rsa-shaped PATTERN is not a filename", `grep -l "id_rsa" README.md CONTRIBUTING.md`, false},
		{"git grep with an .env*-shaped PATTERN is not a filename", `git grep -n "\.env\*" internal/policy`, false},
		{"grep -E pattern matching diff +/- lines is not a filename glob", `git diff HEAD~1 HEAD | grep -E '^[+-]'`, false},
		// Paired bypass: the reader's PATTERN position is exempt, but a
		// later, genuine positional file argument is still checked.
		{"paired bypass: id_rsa as a genuine second positional file argument is still refused", `grep -l pattern id_rsa`, true},
		{"paired bypass: jq's own trailing file argument is still checked", `jq -r '.[] | .name' .env`, true},
		// Paired bypass: grep's -f flag consumes the NEXT word as a
		// real file argument (a pattern-file), not an implicit bare
		// pattern position — its value must stay checked, not be
		// exempted as if it were the pattern itself.
		{"paired bypass: grep -f's own file-valued flag argument is still checked", `grep -f .env data.txt`, true},
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

// TestEvaluateHookCaseStatementPatternArmNotACommand is
// command-policy:case-statement-pattern-arm-not-a-command: a case
// statement's own PATTERN) arm — including one that happens to spell
// the name of a Bound-independent, zero-argument-triggers-a-refusal
// rule this package already has (set/export/env) — is bash's own
// pattern-arm syntax, never a command invocation with no arguments.
func TestEvaluateHookCaseStatementPatternArmNotACommand(t *testing.T) {
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"a case arm literally named set is not the set builtin", "case \"$1\" in\n  set)\n    echo arming\n    ;;\nesac", false},
		{"a case arm literally named env is not the env dump", "case \"$1\" in\n  env)\n    echo showing\n    ;;\nesac", false},
		{"alternated patterns (a|b) are still recognized as pattern text", "case \"$1\" in\n  set|export)\n    echo arming\n    ;;\nesac", false},
		{"a nested case statement inside an arm body is still fully parsed", "case \"$1\" in\n  a)\n    case \"$2\" in\n      set) echo inner ;;\n    esac\n    ;;\nesac", false},
		// Paired bypass: a real command inside an arm's own body is
		// still evaluated exactly like any other command — the fix
		// only discards the PATTERN word itself, never the body that
		// follows it.
		{"paired bypass: a secret-file read inside a case arm's body is still refused", "case \"$1\" in\n  set)\n    cat .env\n    ;;\nesac", true},
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

// TestEvaluateHookWrappedCpassRunFullParity closes the gap the review
// found in this round's own audit: EvaluateHook previously skipped the
// full Evaluate call (with its fd-alias and glob-expansion mechanisms,
// which hookWalk's own lighter per-word scan does not implement) for a
// command that itself wraps `cpass run`, relying only on hookWalk —
// which caught neither an fd-alias reveal nor a glob-expansion reveal
// for that specific shape. Evaluate now always runs, so these are
// caught by the hook itself before the `cpass run` subprocess starts,
// not only once cpass run's own execution-time check runs a moment
// later inside it.
func TestEvaluateHookWrappedCpassRunFullParity(t *testing.T) {
	dotenv := "." + "env"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, dotenv), []byte("STRIPE_LIVE=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"cpass-run-wrapped fd-alias reveal is refused before the subprocess starts",
			"cpass run -- bash -c 'exec 3< " + dotenv + "; cat <&3'", true},
		{"cpass-run-wrapped glob-expansion reveal is refused before the subprocess starts",
			"cpass run -- bash -c 'cat .en?'", true},
		{"cpass-run-wrapped invocation with nothing dangerous stays allowed",
			"cpass run -- bash -c 'echo hello'", false},
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

// TestEvaluateHookReaderNameCoincidentalSubcommandMatch pins a KNOWN,
// ACCEPTED over-refusal (see readerWordRefusal's own doc comment and
// docs/THREATS.md): a multi-level CLI's own subcommand that happens to
// share a name with a reader program (`aws logs tail`) is
// indistinguishable, by this package's flat per-word scan, from a
// genuine invocation of that reader behind an unenumerated wrapper
// (`find . -exec tail .env \;`) — narrowing the check enough to
// exclude one would reopen the other, so this stays a deliberate,
// disclosed trade-off. This test exists so a future change to that
// trade-off is a conscious edit here, not a silent behavior change.
func TestEvaluateHookReaderNameCoincidentalSubcommandMatch(t *testing.T) {
	command := `aws logs tail /aws/lambda/myfunction --filter-pattern .env`
	if err := EvaluateHook(command); err == nil {
		t.Fatalf("command %q: expected the documented, accepted over-refusal (readerWordRefusal treats \"tail\" as a reader invocation), got allowed", command)
	}
}

// TestEvaluateHookMaxDepthFailsClosed is the hook-layer half of
// TestMaxDepthFailsClosed (policy_test.go): a command nested more than
// maxDepth shells/substitutions deep now refuses rather than silently
// running unchecked past that point. Nested via "eval" prefixes (see
// TestMaxDepthFailsClosed's doc comment) rather than repeated `sh -c
// "..."` wrapping, which would need real, non-naive recursive quote
// escaping this test has no need to model.
func TestEvaluateHookMaxDepthFailsClosed(t *testing.T) {
	deep := strings.Repeat("eval ", maxDepth+4) + "echo hi"
	if err := EvaluateHook(deep); err == nil {
		t.Fatalf("a command nested past maxDepth should refuse, not silently allow")
	}
	shallow := strings.Repeat("eval ", maxDepth-4) + "echo hi"
	if err := EvaluateHook(shallow); err != nil {
		t.Fatalf("a command within maxDepth with nothing dangerous should stay allowed: %v", err)
	}
}

// TestEvaluateHookIFSWordSplitting is
// command-policy:ifs-word-splitting-bypass at the PreToolUse hook layer
// (2026-09-22 audit, round 3): the hook's own EvaluateHook wraps a raw
// Bash command string as `sh -c command` and judges it through the same
// shared Evaluate/splitCommands this package uses everywhere else, so
// the tokenizer fix closes this at the hook layer with no separate hook
// logic needed.
func TestEvaluateHookIFSWordSplitting(t *testing.T) {
	dotenv := "." + "env"
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"braced ${IFS} glues cat to the secret file", "cat${IFS}" + dotenv, true},
		{"bare $IFS glues cat to the secret file", "cat$IFS" + dotenv, true},
		{"generalizes to another reader/secret-file pair", "less$IFS.pem", true},
		// Paired benign: the same splitting mechanism around nothing
		// dangerous stays allowed.
		{"IFS splitting around benign text is allowed", "echo${IFS}hello", false},
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

// TestEvaluateHookReadBuiltinAndFDRedirection is
// command-policy:read-builtin-and-fd-redirection-bypass at the
// PreToolUse hook layer (2026-09-22 audit, round 3), mirroring
// TestReadMapfileReadarrayBuiltins and TestExecFDRedirectionAlias in
// policy_test.go — reached through EvaluateHook's own wrap-and-Evaluate
// path, with no separate hook logic needed.
func TestEvaluateHookReadBuiltinAndFDRedirection(t *testing.T) {
	dotenv := "." + "env"
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"read builtin via redirect reads a secret file", `read -r line < ` + dotenv, true},
		{"mapfile via redirect reads a secret file", `mapfile -t lines < ` + dotenv, true},
		{"readarray via redirect reads a secret file", `readarray -t lines < ` + dotenv, true},
		{"exec fd bind then alias reads a secret file", "exec 3< " + dotenv + "; cat <&3", true},
		{"exec named-fd bind then alias reads a secret file", "exec {fd}< " + dotenv + "; cat <&$fd", true},
		// Paired benign shapes.
		{"read builtin on an unrelated file is allowed", `read -r line < notes.txt`, false},
		{"exec binds an unrelated file; alias read stays allowed", "exec 3< notes.txt; cat <&3", false},
		{"an untracked fd alias with no matching exec bind is allowed", "cat <&9", false},
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

// TestEvaluateHookShellBehindUnenumeratedWrapper is
// command-policy:evaluate-shell-behind-unenumerated-wrapper-parity-gap
// at the PreToolUse hook layer (2026-09-22 audit, round 3): hookWalk
// already caught this by structural accident (its own per-word loop
// checks shells[prog] alongside readers[prog]) even before this round's
// Evaluate-side fix, so this pins that hookWalk keeps doing so — the
// real fix in this round is Evaluate's own parity, covered above at the
// unit level and by cpass run's e2e coverage.
func TestEvaluateHookShellBehindUnenumeratedWrapper(t *testing.T) {
	dotenv := "." + "env"
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"unenumerated wrapper hides a shell invocation", "totally-unenumerable-shim sh -c 'cat " + dotenv + "'", true},
		{"unenumerated wrapper with a safe shell invocation is allowed", "totally-unenumerable-shim sh -c 'echo hello'", false},
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

// TestEvaluateHookSecretFileGlobExpansion is
// command-policy:shell-glob-expansion-hides-filename at the PreToolUse
// hook layer (2026-09-22 audit, round 3): EvaluateHook has no explicit
// cwd parameter, so it (like cpass run itself) falls back to this
// process's own os.Getwd() — t.Chdir puts that real cwd where a real
// secret file the glob should resolve to actually lives.
func TestEvaluateHookSecretFileGlobExpansion(t *testing.T) {
	dotenv := "." + "env"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, dotenv), []byte("STRIPE_LIVE=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	cases := []struct {
		name    string
		command string
		refused bool
	}{
		{"question-mark glob expands to the real secret file", "cat .en?", true},
		{"star glob expands to the real secret file", "cat .e*", true},
		{"glob pattern matching only a benign file is allowed", "cat *.txt", false},
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
