// Package policy decides whether a command an Agent wants to run may
// proceed: it refuses commands that would reveal a Secret rather than use
// it, read a Secret-bearing file directly, or carry a raw Secret-shaped
// literal. The same evaluator (Evaluate) serves cpass run, the MCP
// server's run_with_secrets/capture tools, and — via EvaluateHook, which
// applies Evaluate's rules plus one more before any value exists to bind —
// the Claude Code PreToolUse hook, so these rules are identical
// everywhere. The one exception is EvaluateHook's refusal of `cpass add`
// given an inline value: it has no equivalent in Evaluate, since only the
// hook inspects a raw Bash command line before cpass has parsed anything.
package policy

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"claudepass/internal/detect"
	"claudepass/internal/vault"
)

// Var is an environment variable a Secret is bound to.
type Var struct {
	Name string
	Kind vault.BindingKind
}

// Input is one command to judge.
type Input struct {
	Argv  []string
	Bound []Var
	// ProtectedDirs are directories (file-Binding run dirs) that readers
	// may not reference by literal path.
	ProtectedDirs []string
}

// Refusal explains why a command was refused. It is an error so the run
// path can return it directly.
type Refusal struct {
	Rule   string
	Advice string
}

func (r *Refusal) Error() string { return "refused: " + r.Rule + " — " + r.Advice }

// Evaluate returns nil when the command may run, or a *Refusal.
func Evaluate(in Input) error {
	// Scan every argument but not argv[0] itself: argv[0] is the program
	// being exec'd, never a value a Handle could stand in for, and real
	// executable paths (a build artifact under a randomly-named temp
	// directory, a versioned tool under a hashed store path) routinely
	// read as high-entropy to the same heuristic that must stay sensitive
	// enough to catch a literal in an argument.
	if len(in.Argv) > 1 {
		if len(detect.Scan(strings.Join(in.Argv[1:], " "))) > 0 {
			return &Refusal{
				Rule:   "the command carries a raw Secret-shaped value",
				Advice: "store it first (`cpass capture`, or paste it so it's Intercepted) and reference it by Handle",
			}
		}
	}
	ev := &evaluator{bound: map[string]vault.BindingKind{}, tainted: map[string]bool{}, protected: in.ProtectedDirs}
	for _, v := range in.Bound {
		ev.bound[v.Name] = v.Kind
	}
	return ev.argv(in.Argv, 0)
}

type evaluator struct {
	bound     map[string]vault.BindingKind
	tainted   map[string]bool // shell variables assigned from a bound variable
	protected []string
}

func (ev *evaluator) underProtected(w string) bool {
	for _, d := range ev.protected {
		if d != "" && strings.HasPrefix(w, d+"/") {
			return true
		}
	}
	return false
}

const maxDepth = 8

var (
	revealPrograms = map[string]bool{"printenv": true}
	shells         = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true}
	wrappers       = map[string]bool{"env": true, "nohup": true, "nice": true, "command": true, "exec": true, "builtin": true, "time": true, "sudo": true, "doas": true}
	printers       = map[string]bool{"echo": true, "printf": true, "print": true}
	readers        = map[string]bool{
		"cat": true, "less": true, "more": true, "head": true, "tail": true, "base64": true, "xxd": true,
		"od": true, "strings": true, "hexdump": true, "bat": true, "tee": true, "cp": true, "nl": true,
		"tac": true, "rev": true, "sort": true, "uniq": true, "cut": true, "awk": true, "sed": true,
		"grep": true, "jq": true, "yq": true, "dd": true, "install": true, "rsync": true, "scp": true,
	}
	procEnviron = regexp.MustCompile(`/proc/(self|\$\$|[0-9]+|[a-z]*\$[A-Za-z_{]*[}]?)/environ`)
	varRef      = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)`)
	assignment  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
)

// secretFileGlobs are basename patterns of files that hold Secret values on
// disk rather than in the Vault. Evaluate (and so cpass run, the MCP
// server, and — via EvaluateHook — the PreToolUse hook) refuses any
// command that would read one directly: doing so bypasses the Vault, and
// the value would land straight in the Agent's Context. Matched with
// filepath.Match against the basename of each argument, so a path like
// "$HOME/.env" is still caught.
var secretFileGlobs = []string{
	".env*", "*.pem", "id_rsa*", "*.key", "credentials*.json", ".netrc", ".npmrc",
}

// sourceBuiltins are shell builtins that execute a file's content in the
// current shell — a second way to pull a Secret-bearing file's content into
// output or environment besides an ordinary reader program. Only
// meaningful inside a shell string (simple), since neither is a real
// argv[0] a subprocess could exec.
var sourceBuiltins = map[string]bool{"source": true, ".": true}

func matchesSecretFile(arg string) bool {
	if strings.HasPrefix(arg, "-") {
		return false
	}
	b := filepath.Base(arg)
	for _, g := range secretFileGlobs {
		if ok, _ := filepath.Match(g, b); ok {
			return true
		}
	}
	return false
}

func secretFileRefusal(prog, arg string) *Refusal {
	if !matchesSecretFile(arg) {
		return nil
	}
	return &Refusal{
		Rule:   prog + " would read " + arg + ", a Secret-bearing file",
		Advice: "use `cpass run` (or the Manifest) instead of reading the file directly",
	}
}

func base(s string) string { return filepath.Base(s) }

// argv judges a command given as an argument vector (no shell involved,
// so $VAR in a word is literal text — but the word may be a shell string).
func (ev *evaluator) argv(argv []string, depth int) error {
	if len(argv) == 0 || depth > maxDepth {
		return nil
	}
	for _, w := range argv {
		if procEnviron.MatchString(w) {
			return &Refusal{Rule: "reads the process environment file", Advice: "use the variable in a command instead of dumping it"}
		}
	}
	prog := base(argv[0])
	if readers[prog] {
		for _, w := range argv[1:] {
			if ev.underProtected(w) {
				return &Refusal{Rule: prog + " would print a Secret file", Advice: "pass the path to the tool that needs the file instead"}
			}
			if r := secretFileRefusal(prog, w); r != nil {
				return r
			}
		}
	}
	switch {
	case revealPrograms[prog]:
		return &Refusal{Rule: prog + " prints environment variables", Advice: "pass the variable to the tool that needs it instead"}
	case prog == "env":
		// env alone dumps; env [VAR=x]... cmd runs cmd.
		rest := argv[1:]
		for len(rest) > 0 && (strings.HasPrefix(rest[0], "-") || assignment.MatchString(rest[0])) {
			if rest[0] == "-0" || rest[0] == "--null" {
				return &Refusal{Rule: "env prints environment variables", Advice: "pass the variable to the tool that needs it instead"}
			}
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return &Refusal{Rule: "env prints environment variables", Advice: "pass the variable to the tool that needs it instead"}
		}
		return ev.argv(rest, depth+1)
	case prog == "timeout" && len(argv) > 2:
		return ev.argv(argv[2:], depth+1)
	case wrappers[prog]:
		return ev.argv(argv[1:], depth+1)
	case shells[prog]:
		if s, ok := shellCommandString(argv[1:]); ok {
			if hasTraceFlag(argv[1:]) {
				return &Refusal{Rule: "shell tracing (-x) echoes expanded variables", Advice: "drop -x"}
			}
			return ev.shell(s, depth+1)
		}
		return nil
	}
	return nil
}

// shellCommandString finds the STRING in `sh [-flags] -c STRING`.
func shellCommandString(args []string) (string, bool) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") && strings.Contains(a, "c") && !strings.HasPrefix(a, "--") {
			if i+1 < len(args) {
				return args[i+1], true
			}
		}
		if !strings.HasPrefix(a, "-") {
			return "", false
		}
	}
	return "", false
}

func hasTraceFlag(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "x") {
			return true
		}
		if a == "-o" {
			continue
		}
		if a == "xtrace" {
			return true
		}
	}
	return false
}

// shell judges a shell command string by splitting it into simple commands
// and judging each, tracking variables assigned from Secrets.
func (ev *evaluator) shell(s string, depth int) error {
	if depth > maxDepth {
		return nil
	}
	for _, simple := range splitCommands(s) {
		if err := ev.simple(simple, depth); err != nil {
			return err
		}
	}
	return nil
}

func (ev *evaluator) simple(words []word, depth int) error {
	if len(words) == 0 {
		return nil
	}
	// Command substitutions are commands too.
	for _, w := range words {
		for _, inner := range w.subs {
			if err := ev.shell(inner, depth+1); err != nil {
				return err
			}
		}
	}
	// Leading assignments: VAR=$SECRET taints VAR.
	i := 0
	for i < len(words) {
		m := assignment.FindStringSubmatch(words[i].raw)
		if m == nil {
			break
		}
		if ev.references(m[2]) != "" {
			ev.tainted[m[1]] = true
		}
		i++
	}
	if i == len(words) {
		return nil
	}
	rest := words[i:]
	prog := base(rest[0].raw)
	args := rest[1:]
	switch {
	case prog == "export" || prog == "declare" || prog == "typeset":
		if len(args) == 0 {
			return &Refusal{Rule: prog + " with no arguments prints all variables", Advice: "name the variable you want to set"}
		}
		for _, a := range args {
			if strings.HasPrefix(a.raw, "-") && strings.Contains(a.raw, "p") {
				return &Refusal{Rule: prog + " -p prints variables", Advice: "name the variable you want to set"}
			}
			if m := assignment.FindStringSubmatch(a.raw); m != nil && ev.references(m[2]) != "" {
				ev.tainted[m[1]] = true
			}
		}
		return nil
	case prog == "set":
		if len(args) == 0 {
			return &Refusal{Rule: "set with no arguments prints all variables", Advice: "use set -e or similar with explicit flags"}
		}
		for _, a := range args {
			if (strings.HasPrefix(a.raw, "-") && !strings.HasPrefix(a.raw, "--") && strings.Contains(a.raw, "x")) || a.raw == "xtrace" {
				return &Refusal{Rule: "set -x echoes expanded variables", Advice: "drop -x"}
			}
		}
		return nil
	case prog == "compgen":
		for _, a := range args {
			if strings.HasPrefix(a.raw, "-") && strings.Contains(a.raw, "v") {
				return &Refusal{Rule: "compgen -v lists variables", Advice: "name the variable you need"}
			}
		}
		return nil
	case prog == "eval":
		var parts []string
		for _, a := range args {
			parts = append(parts, a.raw)
		}
		return ev.shell(strings.Join(parts, " "), depth+1)
	case printers[prog]:
		for _, a := range args {
			if v := ev.references(a.raw); v != "" {
				return &Refusal{Rule: fmt.Sprintf("%s would print $%s", prog, v), Advice: "pass the variable to the tool that needs it instead"}
			}
		}
		return nil
	case readers[prog]:
		for _, a := range args {
			if v := ev.referencesFile(a.raw); v != "" {
				return &Refusal{Rule: fmt.Sprintf("%s would print the file behind $%s", prog, v), Advice: "pass the path to the tool that needs the file instead"}
			}
			if ev.underProtected(a.raw) {
				return &Refusal{Rule: prog + " would print a Secret file", Advice: "pass the path to the tool that needs the file instead"}
			}
			if r := secretFileRefusal(prog, a.raw); r != nil {
				return r
			}
		}
	case sourceBuiltins[prog]:
		for _, a := range args {
			if r := secretFileRefusal(prog, a.raw); r != nil {
				return r
			}
		}
	}
	// Anything else: judge as an argv, so nested shells, env, printenv apply.
	argv := make([]string, len(rest))
	for i, w := range rest {
		argv[i] = w.raw
	}
	return ev.argv(argv, depth+1)
}

// references returns the first bound or tainted variable referenced in s.
func (ev *evaluator) references(s string) string {
	for _, m := range varRef.FindAllStringSubmatch(s, -1) {
		if _, ok := ev.bound[m[1]]; ok {
			return m[1]
		}
		if ev.tainted[m[1]] {
			return m[1]
		}
	}
	return ""
}

// referencesFile returns the first file-bound variable referenced in s.
func (ev *evaluator) referencesFile(s string) string {
	for _, m := range varRef.FindAllStringSubmatch(s, -1) {
		if k, ok := ev.bound[m[1]]; ok && k == vault.BindFile {
			return m[1]
		}
	}
	return ""
}
