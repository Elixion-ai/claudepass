package e2e

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// hookJSON builds a Claude Code UserPromptSubmit hook payload. Real hook
// invocations carry more fields (session_id, transcript_path, cwd,
// hook_event_name); intercept only reads prompt, so tests below that need
// the full shape build it explicitly instead.
func hookJSON(prompt string) []byte {
	b, err := json.Marshal(map[string]string{"prompt": prompt})
	if err != nil {
		panic(err)
	}
	return b
}

const (
	interceptStripe1 = "sk_live_51H8xJ2eZvKYlo2CTinterceptVALUEabc111"
	interceptStripe2 = "sk_live_51H8xJ2eZvKYlo2CTinterceptVALUEabc222"
	interceptGithub  = "ghp_1234567890abcdefghijklmnopqrstuvwxyz99"
	interceptEntropy = "aB3xQ9mK2pL7vN4zR8tY1wU6sD0fG5hJ3kM"
)

func TestInterceptStripeKeyBlocksStoresAndNeverLeaksTheValue(t *testing.T) {
	ve := newVault(t)
	prompt := "here is my key " + interceptStripe1 + " please use it"
	r := ve.run(hookJSON(prompt), "intercept")
	if r.code != 2 {
		t.Fatalf("want exit 2, got %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, interceptStripe1) {
		t.Fatalf("value leaked to output: %s", r)
	}
	if !strings.Contains(r.stderr, "stripe/live") {
		t.Fatalf("stderr should name the handle: %s", r)
	}
	if !strings.Contains(r.stderr, "resubmit using the Handle") || !strings.Contains(r.stderr, "!!") {
		t.Fatalf("stderr should explain how to proceed: %s", r)
	}
	ls := ve.run(nil, "ls")
	if !strings.Contains(ls.stdout, "stripe/live") {
		t.Fatalf("vault should gain stripe/live: %s", ls)
	}
}

func TestInterceptRealHookJSONFixture(t *testing.T) {
	ve := newVault(t)
	raw, err := json.Marshal(map[string]string{
		"session_id":      "test-session-abc123",
		"transcript_path": "/Users/x/.claude/projects/foo/test-session-abc123.jsonl",
		"cwd":             "/Users/x/project",
		"hook_event_name": "UserPromptSubmit",
		"prompt":          "my key is " + interceptStripe1 + ", help me wire it up",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := ve.run(raw, "intercept")
	if r.code != 2 {
		t.Fatalf("want exit 2, got %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, interceptStripe1) {
		t.Fatalf("value leaked: %s", r)
	}
	if !strings.Contains(r.stderr, "stripe/live") {
		t.Fatalf("stderr: %s", r)
	}
}

func TestInterceptCleanPromptExitsZeroSilently(t *testing.T) {
	ve := newVault(t)
	r := ve.run(hookJSON("just a normal question about Go generics, nothing secret here"), "intercept")
	if r.code != 0 || r.stdout != "" || r.stderr != "" {
		t.Fatalf("clean prompt should pass through silently: %s", r)
	}
}

func TestInterceptInvalidJSONIsUsageError(t *testing.T) {
	ve := newVault(t)
	r := ve.run([]byte("this is not json"), "intercept")
	if r.code != 2 || !strings.Contains(r.stderr, "invalid hook JSON") {
		t.Fatalf("want usage error naming the JSON problem: %s", r)
	}
}

func TestInterceptBypassPrefixPassesThroughAndMarksExposed(t *testing.T) {
	ve := newVault(t)
	r := ve.run(hookJSON("!! "+interceptStripe1), "intercept")
	if r.code != 0 {
		t.Fatalf("bypass should exit 0, got %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, interceptStripe1) {
		t.Fatalf("value leaked: %s", r)
	}
	exp := ve.run(nil, "exposed")
	if exp.code != 0 || !strings.Contains(exp.stdout, "stripe/live") || !strings.Contains(exp.stdout, "reason=bypass") {
		t.Fatalf("cpass exposed after bypass: %s", exp)
	}
}

func TestInterceptBypassNeverBlocksEvenWhenVaultLocked(t *testing.T) {
	ve := newVault(t)
	ve.key = ""
	r := ve.run(hookJSON("!! "+interceptStripe1), "intercept")
	if r.code != 0 {
		t.Fatalf("bypass must always exit 0, got %s", r)
	}
}

func TestInterceptLockedVaultRefusesOnHitWithoutLeaking(t *testing.T) {
	ve := newVault(t)
	ve.key = ""
	r := ve.run(hookJSON(interceptStripe1), "intercept")
	if r.code == 0 {
		t.Fatalf("locked vault should not exit 0 on a hit: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, interceptStripe1) {
		t.Fatalf("value leaked: %s", r)
	}
	if !strings.Contains(r.stderr, "locked") {
		t.Fatalf("want a locked message: %s", r)
	}
}

func TestInterceptHandleCollisionAppendsSuffix(t *testing.T) {
	ve := newVault(t)
	if r := ve.run(hookJSON(interceptStripe1), "intercept"); r.code != 2 {
		t.Fatalf("first intercept: %s", r)
	}
	r := ve.run(hookJSON(interceptStripe2), "intercept")
	if r.code != 2 {
		t.Fatalf("second intercept: %s", r)
	}
	if !strings.Contains(r.stderr, "stripe/live-2") {
		t.Fatalf("want collision suffix in stderr: %s", r)
	}
	ls := ve.run(nil, "ls")
	if !strings.Contains(ls.stdout, "stripe/live\n") || !strings.Contains(ls.stdout, "stripe/live-2") {
		t.Fatalf("vault should hold both handles: %s", ls)
	}
}

func TestInterceptMultipleHitsInOnePrompt(t *testing.T) {
	ve := newVault(t)
	prompt := "stripe key " + interceptStripe1 + " and github token " + interceptGithub + " both leaked"
	r := ve.run(hookJSON(prompt), "intercept")
	if r.code != 2 {
		t.Fatalf("want exit 2: %s", r)
	}
	if !strings.Contains(r.stderr, "stripe/live") || !strings.Contains(r.stderr, "github/token") {
		t.Fatalf("stderr should name both handles: %s", r)
	}
	// docs/CLI-STYLE.md's Intercept row: multiple items are plain
	// comma-joined ("<kind> as <handle>, <kind> as <handle>"), not "a and b".
	want := "cpass: stored Stripe live key as stripe/live, GitHub token as github/token; " +
		"resubmit using the Handle, or prefix with !! to send anyway\n"
	if r.stderr != want {
		t.Fatalf("stderr grammar = %q, want %q", r.stderr, want)
	}
	ls := ve.run(nil, "ls")
	if !strings.Contains(ls.stdout, "stripe/live") || !strings.Contains(ls.stdout, "github/token") {
		t.Fatalf("vault should gain both handles: %s", ls)
	}
}

// Blocking on generic entropy stops the user's work on every prompt that
// carries an ordinary high-entropy token (a tool-call id, a UUID, a git
// SHA, a base64 blob, an automated <task-notification>), so Intercept
// blocks ONLY on high-confidence provider-key prefixes and PEM blocks. A
// generic high-entropy value with no known prefix now passes through and is
// not stored — the honest trade recorded in docs/THREATS.md.
func TestInterceptGenericHighEntropyPassesThrough(t *testing.T) {
	ve := newVault(t)
	prompt := "temp value " + interceptEntropy + " was pasted by mistake, sorry"
	r := ve.run(hookJSON(prompt), "intercept")
	if r.code != 0 {
		t.Fatalf("generic high-entropy value must pass through, got exit %d: %s", r.code, r)
	}
	if ls := ve.run(nil, "ls"); regexp.MustCompile(`inbox/`).MatchString(ls.stdout) {
		t.Fatalf("nothing should be stored: %s", ls)
	}
}

// Regression for the false positive seen in a live weedvader session: an
// automated <task-notification> whose tool-use id / UUID path hash tripped
// the entropy heuristic and blocked the prompt.
func TestInterceptDoesNotBlockAgentEnvelopes(t *testing.T) {
	ve := newVault(t)
	cases := map[string]string{
		"task-notification": `<task-notification><task-id>b1zq8tvq2</task-id>` +
			`<tool-use-id>toolu_016otzT3s4YhS1rGaRRijw3b</tool-use-id>` +
			`<output-file>/private/tmp/claude-501/-Users-elix-projects-weedvader/` +
			`2016568e-289d-45d5-9b92-bf0a21087bc4/tasks/b1zq8tvq2.output</output-file>` +
			`<status>completed</status></task-notification>`,
		"tool id":     "the call toolu_016otzT3s4YhS1rGaRRijw3b returned",
		"uuid":        "run 2016568e-289d-45d5-9b92-bf0a21087bc4 finished",
		"git sha":     "reverting to commit a7c4221af93f7cf9f9343b2023c648f2fbc0996b now",
		"base64 blob": "payload eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9aGVsbG8gd29ybGQ",
		"container":   "docker image sha256:9f2e4c1b8a7d6e5f0c3b2a1908d7e6f5c4b3a29180706f5e4d3c2b1a09876543",
	}
	for name, prompt := range cases {
		t.Run(name, func(t *testing.T) {
			r := ve.run(hookJSON(prompt), "intercept")
			if r.code != 0 {
				t.Fatalf("%s must pass through, got exit %d: %s", name, r.code, r)
			}
		})
	}
	if ls := ve.run(nil, "ls"); strings.TrimSpace(ls.stdout) != "" {
		t.Fatalf("no envelope should have stored anything: %s", ls)
	}
}

// Known-prefix secrets and PEM blocks still block, even inside an envelope.
func TestInterceptStillBlocksKnownSecrets(t *testing.T) {
	ve := newVault(t)
	r := ve.run(hookJSON("here is the key sk_live_51ABCdefGHIjklMNOpqrSTUvwx00 for prod"), "intercept")
	if r.code != 2 {
		t.Fatalf("a real Stripe key must block, got exit %d: %s", r.code, r)
	}
	if ls := ve.run(nil, "ls"); !strings.Contains(ls.stdout, "stripe/live") {
		t.Fatalf("want stripe/live stored: %s", ls)
	}
}

func TestInterceptPEMBlockStoredWithoutLeakingBody(t *testing.T) {
	ve := newVault(t)
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw\n-----END PRIVATE KEY-----"
	r := ve.run(hookJSON("here's our service account key:\n"+pem), "intercept")
	if r.code != 2 {
		t.Fatalf("want exit 2: %s", r)
	}
	if strings.Contains(r.stderr, "BEGIN PRIVATE KEY") {
		t.Fatalf("stderr should not contain the PEM body: %s", r)
	}
	ls := ve.run(nil, "ls")
	if !strings.Contains(ls.stdout, "pem/key") {
		t.Fatalf("vault should gain pem/key: %s", ls)
	}
}

// exposed / rotate-done / mark-exposed, and the cpass run rotation nag.

func TestMarkExposedListedAndRotateDoneClears(t *testing.T) {
	ve := newVault(t)
	ve.add("db/url", "postgres://user:pw@host/db-name")
	if r := ve.run(nil, "mark-exposed", "db/url", "--reason", "printed-in-log"); r.code != 0 {
		t.Fatalf("mark-exposed: %s", r)
	}
	r := ve.run(nil, "exposed")
	if r.code != 0 || !strings.Contains(r.stdout, "db/url") || !strings.Contains(r.stdout, "reason=printed-in-log") {
		t.Fatalf("exposed: %s", r)
	}
	if r := ve.run(nil, "rotate-done", "db/url"); r.code != 0 {
		t.Fatalf("rotate-done: %s", r)
	}
	r = ve.run(nil, "exposed")
	if strings.Contains(r.stdout, "db/url") {
		t.Fatalf("still exposed after rotate-done: %s", r)
	}
}

func TestMarkExposedUnknownHandle(t *testing.T) {
	ve := newVault(t)
	r := ve.run(nil, "mark-exposed", "nope/none", "--reason", "x")
	if r.code == 0 || !strings.Contains(r.stderr, "no such handle") {
		t.Fatalf("want no-such-handle error: %s", r)
	}
}

func TestRunNagUsesIssueWordingWithDateAndAppearsOnce(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", "sk_live_51H8xJ2eZvKYlo2CTnagWordingValueabc")
	if r := ve.run(nil, "mark-exposed", "stripe/live", "--reason", "manual"); r.code != 0 {
		t.Fatalf("mark-exposed: %s", r)
	}
	r := ve.run(nil, "run", "--with", "stripe/live", "--", helperBin)
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	re := regexp.MustCompile(`cpass: stripe/live is Exposed since \d{4}-\d{2}-\d{2}, rotate it`)
	if !re.MatchString(r.stderr) {
		t.Fatalf("nag wording: %s", r)
	}
	if n := strings.Count(r.stderr, "is Exposed since"); n != 1 {
		t.Fatalf("want nag exactly once per invocation, got %d: %s", n, r)
	}
}

func TestRunNoNagWhenNotExposed(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", "sk_live_51H8xJ2eZvKYlo2CTnoNagValueabcdefgh")
	r := ve.run(nil, "run", "--with", "stripe/live", "--", helperBin)
	if r.code != 0 {
		t.Fatalf("run: %s", r)
	}
	if strings.Contains(r.stderr, "is Exposed") {
		t.Fatalf("should not nag when not Exposed: %s", r)
	}
}
