package policy

import "testing"

// FuzzSplitCommands feeds arbitrary strings through the shared tokenizer,
// seeded from TestSplitCommands and TestEvaluate's own table. It asserts
// two things: splitCommands never panics on adversarial input, and no
// amount of fuzzed noise around a known reveal-only command can make that
// command invisible to Evaluate. A known-dangerous command is prepended,
// never appended: a single-pass tokenizer with no backtracking can't let
// anything that comes after change how a fixed prefix was already
// tokenized (an unterminated quote later in the fuzzed suffix, for
// example, only ever swallows text after it), so `<dangerous>; <fuzzed>`
// always yields the dangerous command as splitCommands' first simple
// command, and Evaluate's own shell() stops at the first refusal.
func FuzzSplitCommands(f *testing.F) {
	seeds := []string{
		`a "b c" 'd e' f\ g; h | i && j > out 2>&1; k $(l m) n`,
		`cat < .env`,
		`f=.env; cat "$f"`,
		"ca\\\nt .env",
		"cmd <<'EOF'\nbody\nEOF\n",
		"cmd <<-EOF\n\tbody\n\tEOF\n",
		`echo $STRIPE_LIVE`,
		`bash -o pipefail -c 'true'`,
		"# a comment\ncmd",
		`cmd <<< "here string"`,
		"",
		";;;",
		"'unterminated",
		`"unterminated`,
		"$(unterminated",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// No panic on any input, however malformed.
		cmds := splitCommands(s)

		// A known reveal-only command prepended to fuzzed noise must
		// always be refused: fuzzed garbage can never hide it.
		wrapped := "cat .env; " + s
		if err := Evaluate(Input{Argv: []string{"sh", "-c", wrapped}}); err == nil {
			t.Fatalf("a leading secret-file read was not refused with trailing fuzzed input %q (cmds=%v)", s, cmds)
		}
	})
}

// FuzzShellCommandString fuzzes the flag-parsing state machine directly:
// two arbitrary argv-style words, with and without a trailing recognisable
// -c string. Its only property is panic-safety (index-out-of-range is the
// main risk given the slicing this function does over combined short-flag
// groups); shellCommandString's fail-closed default is already exercised
// by TestShellInvocationUnrecognizedShapeRefuses and FuzzSplitCommands
// above.
func FuzzShellCommandString(f *testing.F) {
	seeds := [][2]string{
		{"-c", "cat .env"},
		{"-xc", "cat .env"},
		{"-euo", "pipefail"},
		{"-o", "pipefail"},
		{"+o", ""},
		{"--noprofile", "--norc"},
		{"--rcfile", "x"},
		{"script.sh", ""},
		{"-", ""},
		{"", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		_, _ = shellCommandString([]string{a, b})
		_, _ = shellCommandString([]string{a, b, "-c", "cat .env"})
	})
}
