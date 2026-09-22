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
		// round 2: reserved-word command-start dispatch
		// (command-policy:control-flow-keyword-bypass)
		"if cat .env; then true; fi",
		"while cat .env; do break; done",
		"until cat .env; do break; done",
		"for i in 1 2 3; do echo $i; done",
		"case $x in a) cat .env ;; esac",
		// round 2: ANSI-C and locale quoting
		// (command-policy:quoting-ansi-c-and-locale-strings)
		`cat $'.env'`,
		`cat $".env"`,
		`cat $'.e\x6ev'`,
		"cat $'unterminated",
		`cat $"unterminated`,
		// round 2: brace expansion
		// (command-policy:brace-expansion-hides-filename)
		"cat .{env,bashrc}",
		"echo {a,b,c}",
		"echo file{1..3}.txt",
		"echo {3..1}",
		"echo {a..z}",
		"echo {a,{b,c}}",
		"echo .{unterminated",
		"echo {,}",
		"echo {0..999999999}",
		// round 2: dynamic command name via a whole-variable reference
		// (command-policy:dynamic-command-name-not-resolved)
		"x='cat .env'; $x",
		"x=cat; $x .env",
		// round 2: here-string reveal through a reader
		// (command-policy:reader-here-string-reveal-bypass)
		"cat <<< $STRIPE_LIVE",
		// round 2: relative path after a same-command cd
		// (command-policy:protecteddirs-relative-path-after-cd)
		"cd /some/dir && cat gcp-sa",
		// round 3: $IFS/${IFS} word-splitting
		// (command-policy:ifs-word-splitting-bypass)
		"cat${IFS}.env",
		"cat$IFS.env",
		"cat$IFS$IFS.env",
		"cat$IFSFOO",
		`cat "${IFS}.env"`,
		"echo${IFS}hello",
		"cat${IFS",
		"cat$IFS",
		// round 3: read/mapfile/readarray and exec fd-redirection
		// (command-policy:read-builtin-and-fd-redirection-bypass)
		"read -r line < .env",
		"mapfile -t lines < .env",
		"readarray -t lines < .env",
		"exec 3< .env; cat <&3",
		"exec {fd}< .env; cat <&$fd",
		"exec {fd}< .env; cat <&${fd}",
		"cat <&9",
		"exec <&3",
		"exec {< .env",
		// round 3: shell behind an unenumerated wrapper
		// (command-policy:evaluate-shell-behind-unenumerated-wrapper-parity-gap)
		"some-unlisted-shim sh -c 'cat .env'",
		// round 3: glob-shaped reader argument
		// (command-policy:shell-glob-expansion-hides-filename)
		"cat .en?",
		"cat .e*",
		"cat [invalid",
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
