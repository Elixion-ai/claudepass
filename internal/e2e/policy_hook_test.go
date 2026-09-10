package e2e

import (
	"encoding/json"
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
