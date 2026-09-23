package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// preToolUseJSON builds a realistic Claude Code PreToolUse Bash hook
// payload: the full shape a real hook invocation carries (session_id,
// transcript_path, cwd, hook_event_name, tool_use_id, ...), even though
// `cpass policy --hook` only reads tool_name and tool_input.command.
func preToolUseJSON(command string) []byte {
	b, err := json.Marshal(map[string]any{
		"session_id":      "test-session-abc123",
		"transcript_path": "/Users/x/.claude/projects/foo/test-session-abc123.jsonl",
		"cwd":             "/Users/x/project",
		"permission_mode": "default",
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input": map[string]any{
			"command":     command,
			"description": "test",
		},
		"tool_use_id": "toolu_01ABC123",
	})
	if err != nil {
		panic(err)
	}
	return b
}

func TestPolicyHookAcceptanceFixtures(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", "sk_live_51H8xJ2eZvKYlo2CThookfixtureVALUEabc")

	cases := []struct {
		name    string
		command string
		blocked bool
		want    string // substring expected in stderr when blocked
	}{
		{"reads a secret file", "cat .env", true, "Secret-bearing file"},
		{"cpass run wrapping a secret file read", "cpass run -- cat .env", true, "Secret-bearing file"},
		{"raw bearer token literal", `curl -H "Authorization: Bearer sk_live_51H8xJ2eZvKYlo2CThookfixtureVALUEabc"`, true, "Secret-shaped value"},
		{"cpass run with a Handle is allowed", `cpass run --with stripe/live -- curl -H "Authorization: Bearer $STRIPE_LIVE" https://api.example.com`, false, ""},
		// CLA-30: an ordinary REST call's URL path (a version segment, a
		// numeric/hex resource id) must not itself look like a raw
		// Secret-shaped literal and trip the hook.
		{"ordinary REST call with a versioned/hex URL path is allowed", `cpass run --with stripe/live -- curl -H "Authorization: Bearer $STRIPE_LIVE" https://api.stripe.com/v1/charges/ch_3Oq5x2AbCdEfGh011`, false, ""},
		{"plain ls is allowed", "ls", false, ""},
		// CLA-62 review: a -c STRING is what actually executes even when
		// a heredoc is attached alongside it — the heredoc must not be
		// able to shadow a dangerous -c string and let it through as a
		// silent, exit-0, unredacted-file-content bypass.
		{"dangerous -c string alongside a benign heredoc is still refused", "bash -c \"cat .env\" <<'EOF'\necho decoy\nEOF\n", true, "Secret-bearing file"},
		// CLA-61 review: an UNQUOTED heredoc delimiter's body is expanded
		// by a real shell — command substitutions included — before it
		// ever reaches the reading program's stdin, regardless of which
		// program that is; a QUOTED delimiter's body stays inert.
		{"unquoted heredoc's command substitution reads .env, attached to cat", "cat <<EOF\n$(cat .env)\nEOF\n", true, "Secret-bearing file"},
		{"unquoted heredoc's command substitution reads .env, attached to a non-reader program", "wc -l <<EOF\n$(cat .env)\nEOF\n", true, "Secret-bearing file"},
		{"quoted heredoc's would-be command substitution stays inert", "cat <<'EOF'\n$(cat .env)\nEOF\n", false, ""},
		// CLA-62 review: shellCommandString's combined-short-option
		// branch used to return the word right after wherever 'c' fell
		// in the group as the -c string the instant it saw the letter —
		// checking "pipefail" and letting the real `cat .env` through.
		{"combined -co: o's value first, c's string is the real command", "bash -co pipefail 'cat .env'", true, "Secret-bearing file"},
		{"combined -oc: same result with the letters swapped", "bash -oc pipefail 'cat .env'", true, "Secret-bearing file"},
		{"combined -co with a safe command is allowed", "bash -co pipefail 'echo hello'", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ve.run(preToolUseJSON(c.command), "policy", "--hook")
			if c.blocked {
				if r.code != 2 {
					t.Fatalf("want exit 2, got %s", r)
				}
				if !strings.HasPrefix(r.stderr, "cpass: refused: ") {
					t.Fatalf("want a refused message on stderr: %s", r)
				}
				if !strings.Contains(r.stderr, c.want) {
					t.Fatalf("stderr should mention %q: %s", c.want, r)
				}
			} else {
				if r.code != 0 {
					t.Fatalf("want exit 0, got %s", r)
				}
				if r.stdout != "" || r.stderr != "" {
					t.Fatalf("allowed command should be silent: %s", r)
				}
			}
			if strings.Contains(r.stdout+r.stderr, "sk_live_51H8xJ2eZvKYlo2CThookfixtureVALUEabc") {
				t.Fatalf("raw Secret value leaked: %s", r)
			}
		})
	}
}

// TestPolicyHookRound2ReviewFindings is the fixer round's e2e proof, at the
// PreToolUse hook layer driven against a real built `cpass policy --hook`
// invocation, for every file-read-class shape the round-2 review reported.
// The two Bound-value-dependent classes (a reveal via a bound variable
// inside a control-flow body, and the here-string reveal) have no Bound
// value at this Bound-independent hook layer to check against at all —
// they are covered above, at the cpass run e2e layer, where a Handle is
// actually bound.
func TestPolicyHookRound2ReviewFindings(t *testing.T) {
	ve := newVault(t)
	cases := []struct {
		name    string
		command string
		blocked bool
		want    string
	}{
		{"if condition reads a secret file", "if cat .env; then true; fi", true, "Secret-bearing file"},
		{"while condition reads a secret file", "while cat .env; do break; done", true, "Secret-bearing file"},
		{"until condition reads a secret file", "until cat .env; do break; done", true, "Secret-bearing file"},
		{"if/then/fi with nothing dangerous is allowed", "if true; then echo hello; fi", false, ""},
		{"ANSI-C quoting names a secret file", `cat $'.env'`, true, "Secret-bearing file"},
		{"locale quoting names a secret file", `cat $".env"`, true, "Secret-bearing file"},
		{"ANSI-C quoting around benign text is allowed", `cat $'hello'`, false, ""},
		{"brace expansion names a secret file", "cat .{env,bashrc}", true, "Secret-bearing file"},
		{"brace expansion with nothing dangerous is allowed", "echo .{txt,md}", false, ""},
		{"a whole variable naming a literal command reading a secret file", `x='cat .env'; $x`, true, "Secret-bearing file"},
		{"a whole variable naming a literal, benign command is allowed", `x='echo hello'; $x`, false, ""},
		{"find -exec cat dotenv is refused at the hook layer", `find . -exec cat .env \;`, true, "Secret-bearing file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ve.run(preToolUseJSON(c.command), "policy", "--hook")
			if c.blocked {
				if r.code != 2 || !strings.HasPrefix(r.stderr, "cpass: refused: ") {
					t.Fatalf("want a refused message on stderr: %s", r)
				}
				if !strings.Contains(r.stderr, c.want) {
					t.Fatalf("stderr should mention %q: %s", c.want, r)
				}
			} else if r.code != 0 {
				t.Fatalf("want exit 0, got %s", r)
			}
		})
	}
}

func TestPolicyHookBlocksCpassAddInlineValue(t *testing.T) {
	ve := newVault(t)
	r := ve.run(preToolUseJSON("cpass add stripe/live sk_live_51H8xJ2eZvKYlo2CTaddinlineVALUEabc"), "policy", "--hook")
	if r.code != 2 {
		t.Fatalf("want exit 2, got %s", r)
	}
	if !strings.Contains(r.stderr, "inline value") {
		t.Fatalf("stderr should explain the inline-value refusal: %s", r)
	}
}

func TestPolicyHookAllowsCpassAddHandleOnly(t *testing.T) {
	ve := newVault(t)
	r := ve.run(preToolUseJSON("cpass add stripe/live"), "policy", "--hook")
	if r.code != 0 {
		t.Fatalf("a bare handle (no inline value) should pass the hook: %s", r)
	}
}

func TestPolicyHookIgnoresNonBashTool(t *testing.T) {
	ve := newVault(t)
	raw, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Read",
		"tool_input":      map[string]any{"file_path": ".env"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ve.run(raw, "policy", "--hook")
	if r.code != 0 {
		t.Fatalf("a non-Bash tool_name should never be judged as a command: %s", r)
	}
}

func TestPolicyHookInvalidJSONIsUsageError(t *testing.T) {
	ve := newVault(t)
	r := ve.run([]byte("not json"), "policy", "--hook")
	if r.code != 2 || !strings.Contains(r.stderr, "invalid hook JSON") {
		t.Fatalf("want a usage error naming the JSON problem: %s", r)
	}
}

func TestPolicyRequiresHookFlag(t *testing.T) {
	ve := newVault(t)
	r := ve.run(preToolUseJSON("ls"), "policy")
	if r.code != 2 {
		t.Fatalf("bare `cpass policy` should be a usage error: %s", r)
	}
}

func TestPolicyHookEmptyCommandAllowed(t *testing.T) {
	ve := newVault(t)
	r := ve.run(preToolUseJSON(""), "policy", "--hook")
	if r.code != 0 {
		t.Fatalf("an empty command should pass through: %s", r)
	}
}

// TestPolicyHookRound3ReviewFindings is the fixer round's e2e proof, at
// the PreToolUse hook layer driven against a real built `cpass policy
// --hook` invocation, for every shape the round-3 (2026-09-22) audit
// reported: command-policy:ifs-word-splitting-bypass,
// command-policy:read-builtin-and-fd-redirection-bypass, and
// command-policy:evaluate-shell-behind-unenumerated-wrapper-parity-gap
// (hookWalk's own per-word loop already caught the wrapper-parity shape
// by structural accident before this round; kept here so the hook-level
// table stays a complete, standalone record of every shape this round
// closes).
func TestPolicyHookRound3ReviewFindings(t *testing.T) {
	ve := newVault(t)
	cases := []struct {
		name    string
		command string
		blocked bool
		want    string
	}{
		{"braced ${IFS} glues cat to a secret file", `cat${IFS}.env`, true, "Secret-bearing file"},
		{"bare $IFS glues cat to a secret file", `cat$IFS.env`, true, "Secret-bearing file"},
		{"IFS splitting around benign text is allowed", `echo${IFS}hello`, false, ""},
		{"read builtin via redirect reads a secret file", `read -r line < .env`, true, "Secret-bearing file"},
		{"mapfile via redirect reads a secret file", `mapfile -t lines < .env`, true, "Secret-bearing file"},
		{"exec fd bind then alias reads a secret file", `exec 3< .env; cat <&3`, true, "Secret-bearing file"},
		{"exec named-fd bind then alias reads a secret file", `exec {fd}< .env; cat <&$fd`, true, "Secret-bearing file"},
		{"an untracked fd alias with no matching exec bind is allowed", `cat <&9; true`, false, ""},
		{"unenumerated wrapper hides a shell invocation", `totally-unenumerable-shim sh -c 'cat .env'`, true, "Secret-bearing file"},
		{"unenumerated wrapper with a safe shell invocation is allowed", `totally-unenumerable-shim sh -c 'echo hello'`, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ve.run(preToolUseJSON(c.command), "policy", "--hook")
			if c.blocked {
				if r.code != 2 || !strings.HasPrefix(r.stderr, "cpass: refused: ") {
					t.Fatalf("want a refused message on stderr: %s", r)
				}
				if !strings.Contains(r.stderr, c.want) {
					t.Fatalf("stderr should mention %q: %s", c.want, r)
				}
			} else if r.code != 0 {
				t.Fatalf("want exit 0, got %s", r)
			}
		})
	}
}

// TestPolicyHookSecretFileGlobExpansion is
// command-policy:shell-glob-expansion-hides-filename's e2e proof at the
// PreToolUse hook layer, with a REAL secret file on disk: a real shell's
// own filename globbing expands a glob-shaped argument against files
// that actually exist before the reading program ever starts, resolved
// here through a same-command `cd` into the real directory (the hook has
// no explicit cwd input of its own, matching how
// TestPolicyRunProtectedDirsRelativePathAfterCd already resolves a
// relative path at this layer).
func TestPolicyHookSecretFileGlobExpansion(t *testing.T) {
	ve := newVault(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("STRIPE_LIVE=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		command string
		blocked bool
	}{
		{"question-mark glob expands to the real secret file", "cd " + dir + " && cat .en?", true},
		{"star glob expands to the real secret file", "cd " + dir + " && cat .e*", true},
		{"glob pattern matching only a benign file is allowed", "cd " + dir + " && cat *.txt", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ve.run(preToolUseJSON(c.command), "policy", "--hook")
			if c.blocked {
				if r.code != 2 || !strings.Contains(r.stderr, "Secret-bearing file") {
					t.Fatalf("want a refused message mentioning the secret file: %s", r)
				}
			} else if r.code != 0 {
				t.Fatalf("want exit 0, got %s", r)
			}
		})
	}
}

// TestPolicyHookSetAsDataNotShellBuiltin is CLA-103's own reported
// trigger, driven against a real built `cpass policy --hook` invocation:
// the owner's transcripts showed the hook reading Python's `set(...)`
// (and other languages'/tools' unrelated uses of the bare word "set") as
// the shell `set` builtin and blocking real work.
func TestPolicyHookSetAsDataNotShellBuiltin(t *testing.T) {
	ve := newVault(t)
	cases := []string{
		`python3 -c "print(set([1, 2]))"`,
		"python3 - <<'EOF'\nitems = set()\nfor x in set([1, 2]):\n    items.add(x)\nEOF",
		`node -e "console.log(new Set([1]))"`,
		"kubectl set image deploy/web web=nginx:1.27",
		`psql -c "UPDATE users SET active = true"`,
		"echo set",
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			r := ve.run(preToolUseJSON(cmd), "policy", "--hook")
			if r.code != 0 {
				t.Fatalf("command %q should be allowed (set/SET here is data, not the shell builtin): %s", cmd, r)
			}
		})
	}
}

// TestPolicyHookXtraceAllowlist is CLA-103's hook-only allowance for
// shell tracing, driven against a real built `cpass policy --hook`
// invocation: `set -x` and a combined short-flag group containing `x`
// are not a reveal worth blocking everyday debugging over at the hook
// layer, where nothing is ever Bound yet. A bare `set` (a different
// rule — it prints every variable unconditionally) still refuses.
func TestPolicyHookXtraceAllowlist(t *testing.T) {
	ve := newVault(t)
	cases := []struct {
		name    string
		command string
		blocked bool
	}{
		{"set -x alone is allowed", "set -x\nls -la", false},
		{"a combined short-flag group containing x is allowed", "set -euxo pipefail\nls", false},
		{"set -x reached through a nested bash -c is allowed", "bash -c 'set -x; ls'", false},
		{"bare set with no arguments still refuses", "set", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ve.run(preToolUseJSON(c.command), "policy", "--hook")
			if c.blocked {
				if r.code != 2 || !strings.HasPrefix(r.stderr, "cpass: refused: ") {
					t.Fatalf("want a refused message on stderr: %s", r)
				}
			} else if r.code != 0 {
				t.Fatalf("want exit 0, got %s", r)
			}
		})
	}
}

// TestPolicyHookWriteThenRun is CLA-103's write-then-run pattern, driven
// against a real built `cpass policy --hook` invocation: writing a
// script via a heredoc-to-file redirect and running it in the same Bash
// tool call must not be refused just because the file genuinely isn't on
// disk yet — this hook runs before either the write or the run has
// actually executed. Resolved through a real temp directory (a same-
// command `cd`, matching TestPolicyHookSecretFileGlobExpansion above) so
// the write and the run share an unambiguous literal path.
func TestPolicyHookWriteThenRun(t *testing.T) {
	ve := newVault(t)
	dir := t.TempDir()
	cases := []struct {
		name    string
		command string
		blocked bool
	}{
		{"a benign script written then run in one call is allowed",
			"cd " + dir + " && cat > t.sh <<'EOF'\n#!/usr/bin/env bash\nset -e\necho ok\nEOF\nbash t.sh", false},
		// Paired bypass: a script written then run that itself reads a
		// secret file is still refused — this is Command Policy
		// correctly resolving and checking the real script content, not
		// merely allowing every write-then-run shape on sight.
		{"paired bypass: a dangerous script written then run is refused",
			"cd " + dir + " && cat > t3.sh <<'EOF'\ncat .env\nEOF\nbash t3.sh", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ve.run(preToolUseJSON(c.command), "policy", "--hook")
			if c.blocked {
				if r.code != 2 || !strings.Contains(r.stderr, "Secret-bearing file") {
					t.Fatalf("want a refused message mentioning the secret file: %s", r)
				}
			} else if r.code != 0 {
				t.Fatalf("want exit 0, got %s", r)
			}
		})
	}
}
