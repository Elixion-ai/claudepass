package policy

import (
	"testing"

	"claudepass/internal/vault"
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
	in.Argv = []string{"gcloud", "--key-file", "/home/u/.config/claudepass/run/abc/gcp-sa"}
	if Evaluate(in) != nil {
		t.Fatal("non-reader may use the path")
	}
}

func TestSplitCommands(t *testing.T) {
	cmds := splitCommands(`a "b c" 'd e' f\ g; h | i && j > out 2>&1; k $(l m) n`)
	want := [][]string{{"a", "b c", "d e", "f g"}, {"h"}, {"i"}, {"j"}, {"k", "$(l m)", "n"}}
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
