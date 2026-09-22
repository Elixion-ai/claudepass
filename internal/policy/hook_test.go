package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		{"quoted heredoc body fed to a non-shell interpreter is data", "python3 - <<'EOF'\ncat .env\nEOF\n", false},

		// refused: secret-bearing file reads
		{"cat dotenv", "cat .env", true},
		{"cat dotenv variant", "cat .env.production", true},
		{"cat dotenv via home var", "cat $HOME/.env", true},
		{"less pem file", "less server.pem", true},
		{"head id_rsa", "head id_rsa", true},
		{"head id_rsa pub", "head id_rsa.pub", true},
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
		// CLA-62/64: a heredoc attached to a shell is evaluated as the
		// script it is, whether or not its delimiter is quoted; one
		// attached to any other program is not (TestEvaluateHook's
		// allowed list covers that half).
		{"quoted heredoc body fed to a shell", "sh <<'EOF'\ncat .env\nEOF\n", true},
		{"unquoted heredoc body fed to a shell", "bash <<EOF\ncat .env\nEOF\n", true},

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
