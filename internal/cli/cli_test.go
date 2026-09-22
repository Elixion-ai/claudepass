package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/policy"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

// refusalGrammar is docs/CLI-STYLE.md's Message grammar row for a Command
// Policy refusal, verbatim.
var refusalGrammar = regexp.MustCompile(`^cpass: refused: .+ — .+$`)

func newPlainEnv() (*env, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	e := &env{stdout: &out, stderr: &errb, outMode: colorNone, errMode: colorNone}
	return e, &out, &errb
}

// TestRefuseMatchesGrammar is W33's table-driven grammar test: every
// refusal message the CLI can emit — the one it constructs itself
// (--unsafe-allow) and every distinct reason internal/policy's evaluator
// can return, sourced by calling the real evaluator rather than copying
// its strings, so this test cannot silently drift from what cpass
// actually prints — must match docs/CLI-STYLE.md's refusal grammar.
func TestRefuseMatchesGrammar(t *testing.T) {
	type literal struct{ what, insteadDo string }
	directCases := []struct {
		name string
		l    literal
	}{
		// The one refusal cpass run/capture construct themselves, rather
		// than forwarding a *policy.Refusal (see runcmd.go, capturecmd.go).
		{"unsafe-allow needs a terminal", literal{"--unsafe-allow needs a terminal", "only a human may skip Command Policy"}},
	}
	for _, c := range directCases {
		t.Run(c.name, func(t *testing.T) {
			e, _, errb := newPlainEnv()
			code := e.refuse(c.l.what, c.l.insteadDo)
			if code != ExitRefused {
				t.Fatalf("refuse returned %d, want ExitRefused (%d)", code, ExitRefused)
			}
			assertRefusalLine(t, errb.String())
		})
	}

	// Every distinct Command Policy refusal cpass run, cpass capture and
	// cpass policy --hook can surface, driven through the real evaluator.
	policyCases := []struct {
		name string
		eval func() error
	}{
		{"raw secret-shaped literal", func() error {
			return policy.Evaluate(policy.Input{Argv: []string{
				"curl", "-H", "Authorization: Bearer sk_live_51H8xJ2eZvKYlo2CTcpassrunliteralVALUEab",
			}})
		}},
		{"reads a secret-bearing file", func() error {
			return policy.Evaluate(policy.Input{Argv: []string{"cat", ".env"}})
		}},
		{"reads a secret-bearing file via shell source", func() error {
			return policy.Evaluate(policy.Input{Argv: []string{"sh", "-c", "source .env"}})
		}},
		{"reads /proc/self/environ", func() error {
			return policy.Evaluate(policy.Input{Argv: []string{"cat", "/proc/self/environ"}})
		}},
		{"printenv dumps the environment", func() error {
			return policy.Evaluate(policy.Input{Argv: []string{"printenv"}})
		}},
		{"env dumps the environment", func() error {
			return policy.Evaluate(policy.Input{Argv: []string{"env"}})
		}},
		{"set -x echoes variables (argv shell)", func() error {
			return policy.Evaluate(policy.Input{Argv: []string{"sh", "-c", "set -x; true"}})
		}},
		{"export -p prints variables", func() error {
			return policy.Evaluate(policy.Input{Argv: []string{"sh", "-c", "export -p"}})
		}},
		{"set with no arguments prints variables", func() error {
			return policy.Evaluate(policy.Input{Argv: []string{"sh", "-c", "set"}})
		}},
		{"compgen -v lists variables", func() error {
			return policy.Evaluate(policy.Input{Argv: []string{"sh", "-c", "compgen -v"}})
		}},
		{"echo would print a bound variable", func() error {
			return policy.Evaluate(policy.Input{
				Argv:  []string{"sh", "-c", "echo $STRIPE_LIVE"},
				Bound: []policy.Var{{Name: "STRIPE_LIVE", Kind: vault.BindEnv}},
			})
		}},
		{"cat would print a bound file variable", func() error {
			return policy.Evaluate(policy.Input{
				Argv:  []string{"sh", "-c", "cat $CRED_FILE"},
				Bound: []policy.Var{{Name: "CRED_FILE", Kind: vault.BindFile}},
			})
		}},
		{"hook: cpass add given an inline value", func() error {
			return policy.EvaluateHook("cpass add stripe/live sk_live_51H8xJ2eZvKYlo2CTaddinlineVALUEabc")
		}},
		{"hook: raw secret-shaped literal", func() error {
			return policy.EvaluateHook(`curl -H "Authorization: Bearer sk_live_51H8xJ2eZvKYlo2CThookfixtureVALUEabc"`)
		}},
	}
	for _, c := range policyCases {
		t.Run(c.name, func(t *testing.T) {
			err := c.eval()
			var ref *policy.Refusal
			if !errors.As(err, &ref) {
				t.Fatalf("expected a *policy.Refusal, got %v (%T)", err, err)
			}
			e, _, errb := newPlainEnv()
			code := e.refuse(ref.Rule, ref.Advice)
			if code != ExitRefused {
				t.Fatalf("refuse returned %d, want ExitRefused (%d)", code, ExitRefused)
			}
			assertRefusalLine(t, errb.String())
		})
	}
}

// assertRefusalLine checks the grammar every internal/e2e refusal
// assertion also relies on: the refused-grammar regex, exactly one line,
// and the literal grammar prefix.
func assertRefusalLine(t *testing.T, got string) {
	t.Helper()
	if !strings.HasPrefix(got, "cpass: refused: ") {
		t.Fatalf("refusal %q missing the cpass: refused: prefix", got)
	}
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("refusal %q should be exactly one line", got)
	}
	if !refusalGrammar.MatchString(strings.TrimSuffix(got, "\n")) {
		t.Fatalf("refusal %q does not match %s", got, refusalGrammar)
	}
}

func TestRefusalTextIsColouredOnlyWhenModeAllows(t *testing.T) {
	e, _, _ := newPlainEnv()
	plain := e.refusalText("x", "y")
	if plain != "cpass: refused: x — y" {
		t.Fatalf("plain refusalText = %q", plain)
	}
	e.errMode = colorTrue
	coloured := e.refusalText("x", "y")
	want := "\x1b[38;2;255;77;77mcpass: refused: x — y\x1b[0m"
	if coloured != want {
		t.Fatalf("coloured refusalText = %q, want %q", coloured, want)
	}
}

func TestNoticeWritesPlainCpassLine(t *testing.T) {
	e, _, errb := newPlainEnv()
	e.notice("%d missing handle(s):", 2)
	if got := errb.String(); got != "cpass: 2 missing handle(s):\n" {
		t.Fatalf("notice output = %q", got)
	}
}

func TestStoredRendersKindAsHandle(t *testing.T) {
	e, _, _ := newPlainEnv()
	if got := e.stored("Stripe live key", "stripe/live"); got != "Stripe live key as stripe/live" {
		t.Fatalf("stored = %q", got)
	}
	e.errMode = color256
	got := e.stored("Stripe live key", "stripe/live")
	want := "\x1b[38;5;245mStripe live key\x1b[0m as \x1b[38;5;208mstripe/live\x1b[0m"
	if got != want {
		t.Fatalf("coloured stored = %q, want %q", got, want)
	}
}

func TestExposedRendersDocsGrammar(t *testing.T) {
	e, _, _ := newPlainEnv()
	got := e.exposed("stripe/live", "2026-01-02")
	want := "cpass: stripe/live is Exposed since 2026-01-02, rotate it"
	if got != want {
		t.Fatalf("exposed = %q, want %q", got, want)
	}
	// Matches the shape internal/run.Run's own Exposed-reminder Fprintf
	// produces byte-for-byte in plain mode, since both implement the same
	// docs/CLI-STYLE.md row.
	runStyle := "cpass: " + "stripe/live" + " is Exposed since " + "2026-01-02" + ", rotate it"
	if got != runStyle {
		t.Fatalf("exposed diverges from internal/run's Exposed-reminder shape: %q vs %q", got, runStyle)
	}
}

func TestLockedRendersDocsGrammar(t *testing.T) {
	e, _, _ := newPlainEnv()
	got := e.locked()
	want := "cpass: vault is locked, run cpass unlock"
	if got != want {
		t.Fatalf("locked = %q, want %q", got, want)
	}
}

// TestPolicyHookRefusalNeverColoured is the regression test for the bug
// where `cpass policy --hook` rendered its refusal through the env's
// TTY-derived errMode: if the hook subprocess's stderr ever happened to
// report as a terminal (a supervisor-attached pty, a developer piping a
// hook payload by hand), Claude Code's PreToolUse block message would
// carry raw ANSI escapes. The hook branch must force colorNone regardless
// of errMode.
func TestPolicyHookRefusalNeverColoured(t *testing.T) {
	var errb bytes.Buffer
	e := &env{
		args:   []string{"--hook"},
		stdin:  strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"cat .env"}}`),
		stdout: &bytes.Buffer{}, stderr: &errb,
		// Simulate stderr somehow reporting as a real terminal: this is
		// exactly the condition that leaked escapes before the fix.
		outMode: colorTrue, errMode: colorTrue,
	}
	code := cmdPolicy(e)
	if code != ExitUsage {
		t.Fatalf("cmdPolicy(cat .env) = %d, want ExitUsage (%d): %s", code, ExitUsage, errb.String())
	}
	if containsESC(errb.String()) {
		t.Fatalf("cpass policy --hook leaked ANSI escapes into the PreToolUse block message: %q", errb.String())
	}
	assertRefusalLine(t, errb.String())
}

// TestInterceptStoredFragmentNeverColoured is the regression test for the
// analogous bug in cmdIntercept: the "<kind> as <handle>" fragment reached
// Claude Code's UserPromptSubmit hook re-display through the env's
// TTY-derived errMode, so it too must always render plain.
func TestInterceptStoredFragmentNeverColoured(t *testing.T) {
	home := t.TempDir()
	t.Setenv(broker.EnvHome, home)
	key := bytes.Repeat([]byte{0x42}, vault.KeySize)
	t.Setenv(broker.EnvKey, base64.StdEncoding.EncodeToString(key))
	vp, err := broker.VaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Create(vp, key); err != nil {
		t.Fatal(err)
	}

	var errb bytes.Buffer
	prompt := `{"prompt":"here's the key: sk_live_51H8xJ2eZvKYlo2CTESTabcdefghijklmno please use it"}`
	e := &env{
		stdin:  strings.NewReader(prompt),
		stdout: &bytes.Buffer{}, stderr: &errb,
		outMode: colorTrue, errMode: colorTrue,
	}
	code := cmdIntercept(e)
	if code != ExitUsage {
		t.Fatalf("cmdIntercept = %d, want ExitUsage (%d): %s", code, ExitUsage, errb.String())
	}
	if containsESC(errb.String()) {
		t.Fatalf("cpass intercept leaked ANSI escapes into the UserPromptSubmit re-display: %q", errb.String())
	}
	if !strings.Contains(errb.String(), "stripe/live") {
		t.Fatalf("intercept output missing expected handle: %q", errb.String())
	}
}

// TestInterceptMultipleStoredFragmentsAreCommaJoined is the regression test
// for docs/CLI-STYLE.md's Intercept row grammar: multiple stored items are
// plain comma-joined ("<kind> as <handle>, <kind> as <handle>"), not the
// earlier joinWithAnd "a, b and c" shape.
func TestInterceptMultipleStoredFragmentsAreCommaJoined(t *testing.T) {
	home := t.TempDir()
	t.Setenv(broker.EnvHome, home)
	key := bytes.Repeat([]byte{0x37}, vault.KeySize)
	t.Setenv(broker.EnvKey, base64.StdEncoding.EncodeToString(key))
	vp, err := broker.VaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Create(vp, key); err != nil {
		t.Fatal(err)
	}

	var errb bytes.Buffer
	prompt := `{"prompt":"stripe key sk_live_51H8xJ2eZvKYlo2CTcommaJoinVALUEabc and ` +
		`github token ghp_1234567890abcdefghijklmnopqrstuvwxyz99 both leaked"}`
	e := &env{
		stdin:  strings.NewReader(prompt),
		stdout: &bytes.Buffer{}, stderr: &errb,
		outMode: colorNone, errMode: colorNone,
	}
	code := cmdIntercept(e)
	if code != ExitUsage {
		t.Fatalf("cmdIntercept = %d, want ExitUsage (%d): %s", code, ExitUsage, errb.String())
	}
	want := "cpass: stored Stripe live key as stripe/live, GitHub token as github/token; " +
		"resubmit using the Handle, or prefix with !! to send anyway\n"
	if errb.String() != want {
		t.Fatalf("stderr = %q, want %q", errb.String(), want)
	}
}

// TestSubcommandFlagErrorsMatchGrammar is the regression test for the bug
// where every subcommand's flag-parse errors bypassed cpass's message
// grammar entirely: flag.FlagSet's default Usage wrote its own raw,
// unprefixed, mixed-case, multi-line text ("flag provided but not
// defined: -bogus\nUsage of ls:\n  -exposed\n\t...") straight to stderr,
// with no "cpass: " prefix at all. usageErr (cli.go) is now the only
// thing that ever gets to print once a FlagSet fails to parse — every one
// of the 27 flag.NewFlagSet call sites across internal/cli is covered
// below by its exact invocation.
func TestSubcommandFlagErrorsMatchGrammar(t *testing.T) {
	cases := [][]string{
		{"init", "--bogus"},
		{"add", "--bogus"},
		{"ls", "--bogus"},
		{"rm", "--bogus"},
		{"mv", "--bogus"},
		{"capture", "--bogus"},
		{"exposed", "--bogus"},
		{"rotate-done", "--bogus"},
		{"mark-exposed", "--bogus"},
		{"import", "--bogus"},
		{"intercept", "--bogus"},
		{"mcp", "--bogus"},
		{"run", "--bogus"},
		{"policy", "--bogus"},
		{"unlock", "--bogus"},
		{"lock", "--bogus"},
		{"broker-serve", "--bogus"},
		{"keychain", "upgrade", "--bogus"},
		{"manifest", "init", "--bogus"},
		{"manifest", "add", "--bogus"},
		{"manifest", "check", "--bogus"},
		{"manifest", "global", "--bogus"},
		{"global", "--bogus"},
		{"local", "--bogus"},
		{"integrate", "codex", "--bogus"},
		{"integrate", "claude", "--bogus"},
		{"integrate", "mcp", "--bogus"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, errb bytes.Buffer
			code := Main(args, strings.NewReader(""), &out, &errb)
			if code != ExitUsage {
				t.Fatalf("%v: exit = %d, want ExitUsage (%d); stdout=%q stderr=%q", args, code, ExitUsage, out.String(), errb.String())
			}
			if out.Len() != 0 {
				t.Fatalf("%v: unexpected stdout %q", args, out.String())
			}
			got := errb.String()
			if !strings.HasPrefix(got, "cpass: ") {
				t.Fatalf("%v: stderr %q missing the cpass: prefix", args, got)
			}
			if strings.Count(got, "\n") != 1 {
				t.Fatalf("%v: stderr %q should be exactly one line", args, got)
			}
			if strings.Contains(got, "Usage of") {
				t.Fatalf("%v: stderr %q leaked flag package's own raw usage text", args, got)
			}
			if containsESC(got) {
				t.Fatalf("%v: stderr %q leaked ANSI escapes", args, got)
			}
		})
	}
}

// TestSubcommandHelpMatchesGrammar is the same regression for -h/--help: a
// bare `cpass ls --help` used to print flag's own "Usage of ls:" block
// with no cpass: prefix. usageErr now prints a one-line "usage: cpass
// ..." synopsis to stdout and exits 0, matching Main's own top-level
// `cpass help`/`-h` handling instead of falling through to flag's output.
func TestSubcommandHelpMatchesGrammar(t *testing.T) {
	for _, flagName := range []string{"-h", "--help"} {
		t.Run(flagName, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := Main([]string{"ls", flagName}, strings.NewReader(""), &out, &errb)
			if code != ExitOK {
				t.Fatalf("cpass ls %s: exit = %d, want ExitOK (%d); stdout=%q stderr=%q", flagName, code, ExitOK, out.String(), errb.String())
			}
			if errb.Len() != 0 {
				t.Fatalf("cpass ls %s: unexpected stderr %q", flagName, errb.String())
			}
			got := out.String()
			if !strings.HasPrefix(got, "usage: cpass ls ") {
				t.Fatalf("cpass ls %s: stdout %q missing the usage synopsis", flagName, got)
			}
			if strings.Contains(got, "Usage of") {
				t.Fatalf("cpass ls %s: stdout %q leaked flag package's own raw usage text", flagName, got)
			}
		})
	}
}

// TestDispatcherHelpMatchesGrammar is the regression test for the bug
// where manifest/keychain/integrate — the three commands that switch on
// e.args[0] as a subcommand name rather than parsing it with a
// flag.FlagSet — had no -h/--help case at all, so -h/--help fell into the
// same "unknown subcommand" branch as a typo and exited ExitUsage instead
// of printing a usage synopsis and exiting 0, like every flag.FlagSet-based
// subcommand's own -h/--help already does via usageErr (see
// TestSubcommandHelpMatchesGrammar above).
func TestDispatcherHelpMatchesGrammar(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		prefix string
	}{
		{"manifest", []string{"manifest"}, "usage: cpass manifest "},
		{"keychain", []string{"keychain"}, "usage: cpass keychain "},
		{"integrate", []string{"integrate"}, "usage: cpass integrate "},
	}
	for _, c := range cases {
		for _, flagName := range []string{"-h", "--help"} {
			t.Run(c.name+" "+flagName, func(t *testing.T) {
				var out, errb bytes.Buffer
				args := append(append([]string{}, c.args...), flagName)
				code := Main(args, strings.NewReader(""), &out, &errb)
				if code != ExitOK {
					t.Fatalf("cpass %s: exit = %d, want ExitOK (%d); stdout=%q stderr=%q", strings.Join(args, " "), code, ExitOK, out.String(), errb.String())
				}
				if errb.Len() != 0 {
					t.Fatalf("cpass %s: unexpected stderr %q", strings.Join(args, " "), errb.String())
				}
				got := out.String()
				if !strings.HasPrefix(got, c.prefix) {
					t.Fatalf("cpass %s: stdout %q missing the usage synopsis", strings.Join(args, " "), got)
				}
				if strings.Contains(got, "unknown") {
					t.Fatalf("cpass %s: stdout %q looks like the unknown-subcommand branch, not help", strings.Join(args, " "), got)
				}
			})
		}
	}
}

// TestLsFlagAfterPositional is the regression test for the bug where
// cmdLs called fs.Parse directly instead of parseInterspersed: Go's flag
// package stops parsing at the first positional, so `cpass ls demo -l`
// silently dropped -l instead of erroring or honouring it. Each case
// asserts the flag-after-positional spelling produces byte-identical
// output to the flag-before-positional spelling every other test in this
// file already exercises.
func TestLsFlagAfterPositional(t *testing.T) {
	home := t.TempDir()
	t.Setenv(broker.EnvHome, home)
	key := bytes.Repeat([]byte{0x11}, vault.KeySize)
	t.Setenv(broker.EnvKey, base64.StdEncoding.EncodeToString(key))
	vp, err := broker.VaultPath()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Create(vp, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Add("demo/one", "value-one", vault.AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Add("demo/two", "value-two", vault.AddOptions{Exposed: "added-exposed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Add("other/three", "value-three", vault.AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (string, string, int) {
		var out, errb bytes.Buffer
		code := Main(args, strings.NewReader(""), &out, &errb)
		return out.String(), errb.String(), code
	}

	cases := []struct {
		name   string
		before []string
		after  []string
	}{
		{"exposed", []string{"ls", "--exposed", "demo"}, []string{"ls", "demo", "--exposed"}},
		{"long", []string{"ls", "-l", "demo"}, []string{"ls", "demo", "-l"}},
		{"global", []string{"ls", "--global", "demo"}, []string{"ls", "demo", "--global"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantOut, wantErr, wantCode := run(c.before...)
			gotOut, gotErr, gotCode := run(c.after...)
			if gotCode != wantCode || gotOut != wantOut || gotErr != wantErr {
				t.Fatalf("%v = (%d, %q, %q), want %v = (%d, %q, %q)",
					c.after, gotCode, gotOut, gotErr, c.before, wantCode, wantOut, wantErr)
			}
			if wantCode != ExitOK {
				t.Fatalf("%v: exit = %d, want ExitOK (%d): %s", c.before, wantCode, ExitOK, wantErr)
			}
		})
	}

	// A second positional beyond the prefix is a usage error, not a
	// silently ignored argument.
	t.Run("extra positional", func(t *testing.T) {
		_, errb, code := run("ls", "demo", "other")
		if code != ExitUsage {
			t.Fatalf("cpass ls demo other: exit = %d, want ExitUsage (%d): %s", code, ExitUsage, errb)
		}
	})
}

func TestUnknownCommandUsesNotice(t *testing.T) {
	var out, errb bytes.Buffer
	code := Main([]string{"not-a-real-command"}, strings.NewReader(""), &out, &errb)
	if code != ExitUsage {
		t.Fatalf("unknown command exit = %d, want %d", code, ExitUsage)
	}
	if !strings.HasPrefix(errb.String(), `cpass: unknown command "not-a-real-command"`+"\n") {
		t.Fatalf("unknown command stderr = %q", errb.String())
	}
}
