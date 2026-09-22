package policy

import (
	"strings"

	"github.com/Elixion-ai/claudepass/internal/detect"
)

// EvaluateHook judges a raw Bash command string from Claude Code's
// PreToolUse hook, run by `cpass policy --hook` before the command ever
// executes and before cpass has bound anything. It refuses a command
// that:
//
//   - reads a Secret-bearing file directly (.env*, *.pem, id_rsa*, *.key,
//     credentials*.json, .netrc, .npmrc) via a reader program or a shell
//     source/. builtin, at any depth (pipelines, nested shells, command
//     substitutions, or arguments to `cpass run`'s own wrapped command) —
//     the same rule Evaluate applies (see the package doc comment),
//     checked here too so it catches a wrapped `cpass run` invocation
//     before that subprocess ever starts, not only once it does;
//   - carries a raw Secret-shaped literal (the CLA-10 detector) — again
//     the same rule Evaluate applies, checked here unconditionally for the
//     same reason;
//   - gives `cpass add` an inline value instead of letting it prompt — the
//     one rule with no equivalent in Evaluate, since only the hook
//     inspects a raw command line before cpass has parsed anything; or
//   - trips one of the ordinary Bound-independent Command Policy rules
//     (env/printenv/set/export dumps, /proc/*/environ, shell tracing) and
//     is not itself a `cpass run` invocation — one that is will have those
//     same rules applied again at execution time, with cpass run's actual
//     Bound vars.
func EvaluateHook(command string) error {
	if strings.TrimSpace(command) == "" {
		return nil
	}
	if r := hookWalk(command, 0); r != nil {
		return r
	}
	// Same raw-literal rule Evaluate applies (see the package doc
	// comment), checked here unconditionally — including when command
	// wraps a `cpass run` invocation, unlike the ordinary rules below —
	// since no Bound var is needed to judge a literal.
	if len(detect.ScanStrict(command)) > 0 {
		return &Refusal{
			Rule:   "the command carries a raw Secret-shaped value",
			Advice: "store it first (`cpass capture`, or paste it so it's Intercepted) and reference it by Handle",
		}
	}
	if !wrapsCpassRun(command) {
		if err := Evaluate(Input{Argv: []string{"sh", "-c", command}}); err != nil {
			return err
		}
	}
	return nil
}

// wrapsCpassRun reports whether any top-level simple command in command is
// a `cpass run` invocation. Command Policy's Bound-independent rules need
// not be pre-applied by the hook for one, since cpass run applies them
// again at execution time with its real Bound vars.
func wrapsCpassRun(command string) bool {
	for _, words := range splitCommands(command) {
		if len(words) >= 2 && base(words[0].raw) == "cpass" && words[1].raw == "run" {
			return true
		}
	}
	return false
}

// hookWalk recurses through command the same way splitCommands' consumers
// elsewhere in this package do — into command substitutions and nested
// `shell -c STRING` invocations — checking every simple command for a
// Secret-file read or a `cpass add` given an inline value. It does not
// touch the Bound/tainted evaluator: those hook-independent checks have no
// Bound vars to work from at this point.
func hookWalk(command string, depth int) *Refusal {
	if depth > maxDepth {
		return nil
	}
	for _, words := range splitCommands(command) {
		if len(words) == 0 {
			continue
		}
		for _, w := range words {
			for _, sub := range w.subs {
				if r := hookWalk(sub, depth+1); r != nil {
					return r
				}
			}
		}
		for i, w := range words {
			prog := base(w.raw)
			if prog == "cpass" && i+1 < len(words) && words[i+1].raw == "add" {
				if r := addInlineValueRefusal(words[i+2:]); r != nil {
					return r
				}
			}
			if readers[prog] || sourceBuiltins[prog] {
				for _, arg := range words[i+1:] {
					if matchesSecretFile(arg.raw) {
						return &Refusal{
							Rule:   w.raw + " would read " + arg.raw + ", a Secret-bearing file",
							Advice: "use `cpass run` (or the Manifest) instead of reading the file directly",
						}
					}
				}
			}
			if shells[prog] {
				raw := make([]string, len(words[i+1:]))
				for j, ww := range words[i+1:] {
					raw[j] = ww.raw
				}
				if s, ok := shellCommandString(raw); ok {
					if r := hookWalk(s, depth+1); r != nil {
						return r
					}
				}
			}
		}
	}
	return nil
}

// addInlineValueRefusal reports whether args (the words after `cpass add`)
// carry a second positional argument — an inline value — beyond the
// Handle. cpass add's own usage is `cpass add <handle> [--binding NAME]
// [--file] [--exposed] [-g]`, so a second positional can only be a value the
// Agent already knows, which defeats the terminal gate cpass add enforces
// on itself.
func addInlineValueRefusal(args []word) *Refusal {
	positionals := 0
	for i := 0; i < len(args); i++ {
		a := args[i].raw
		switch {
		case a == "--file" || a == "-file" || a == "--exposed" || a == "-exposed",
			a == "--global" || a == "-global" || a == "-g" || a == "--g":
			// boolean flags, no value
		case a == "--binding" || a == "-binding":
			i++ // skip the flag's value too
		case strings.HasPrefix(a, "--binding=") || strings.HasPrefix(a, "-binding="):
			// value attached, nothing more to skip
		case strings.HasPrefix(a, "-"):
			// unrecognised flag; ignore rather than guess
		default:
			positionals++
		}
	}
	if positionals > 1 {
		return &Refusal{
			Rule:   "cpass add given an inline value",
			Advice: "let `cpass add <handle>` prompt for the value, or use `cpass capture <handle> -- <command>`",
		}
	}
	return nil
}
