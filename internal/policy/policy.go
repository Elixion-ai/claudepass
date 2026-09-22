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
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Elixion-ai/claudepass/internal/detect"
	"github.com/Elixion-ai/claudepass/internal/vault"
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
		if len(detect.ScanStrict(strings.Join(in.Argv[1:], " "))) > 0 {
			return &Refusal{
				Rule:   "the command carries a raw Secret-shaped value",
				Advice: "store it first (`cpass capture`, or paste it so it's Intercepted) and reference it by Handle",
			}
		}
	}
	ev := &evaluator{
		bound:     map[string]vault.BindingKind{},
		tainted:   map[string]bool{},
		literals:  map[string]string{},
		protected: in.ProtectedDirs,
	}
	for _, v := range in.Bound {
		ev.bound[v.Name] = v.Kind
	}
	return ev.argv(in.Argv, 0)
}

type evaluator struct {
	bound   map[string]vault.BindingKind
	tainted map[string]bool // shell variables assigned from a bound variable
	// literals holds shell variables assigned a plain string with no
	// variable reference of their own (f=.env, never f=$SOMETHING) — so a
	// later bare $f/${f} can be resolved back to that literal filename
	// (resolveLiteral), the way secretFileRefusal judges an argument
	// written directly as .env.
	literals  map[string]string
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
	// indirectVarRef matches Bash indirect expansion, ${!NAME} — NAME's
	// own value (resolved through literals) names the variable actually
	// being read, e.g. `x=STRIPE_LIVE; echo ${!x}` reads $STRIPE_LIVE.
	// Unlike varRef this form always requires both braces.
	indirectVarRef = regexp.MustCompile(`\$\{!([A-Za-z_][A-Za-z0-9_]*)\}`)
	assignment     = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	// identRe matches a bare shell identifier, used by wholeVarRef to
	// recognise a word that is exactly one variable reference and nothing
	// else.
	identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
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

// secretFileExcludeGlobs are basename patterns that would otherwise match
// secretFileGlobs but are conventionally the *non*-secret counterpart of
// one — a public key, or a template meant to be committed and read freely.
// Checked first, so e.g. id_rsa.pub and .env.example are never refused:
// neither was ever meant to be Vaulted, so "use cpass run instead" would be
// a dead end for both.
var secretFileExcludeGlobs = []string{
	"*.pub",
	".env.example", ".env.sample", ".env.template", ".env.dist",
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
	for _, g := range secretFileExcludeGlobs {
		if ok, _ := filepath.Match(g, b); ok {
			return false
		}
	}
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
		content, refuse := shellCommandString(argv[1:])
		if refuse {
			return &Refusal{
				Rule:   prog + "'s invocation shape can't be checked statically",
				Advice: `use -c "..." or a readable script file under 1 MiB (cpass reads and checks it) instead`,
			}
		}
		if hasTraceFlag(argv[1:]) {
			return &Refusal{Rule: "shell tracing (-x) echoes expanded variables", Advice: "drop -x"}
		}
		return ev.shell(content, depth+1)
	}
	return nil
}

// maxStaticScriptSize bounds how large a script-by-path file
// shellCommandString will read and statically evaluate. A larger file
// makes the shape unresolvable and the invocation is refused rather than
// silently allowed unchecked (see docs/THREATS.md).
const maxStaticScriptSize = 1 << 20 // 1 MiB

// shellCommandString resolves what a `<shell> [options...] [-c STRING |
// script-path [args...]]` invocation statically evaluates to: the -c
// string, or a script file's own contents (script-by-path — read only when
// it names a readable regular file no larger than maxStaticScriptSize; this
// is what keeps `cpass run -- bash script.sh` working, the core use case,
// instead of being refused just because it isn't an inline -c string).
// refuse is true, with content=="", when the shape cannot be resolved that
// way at all: an unrecognised option, an -o/-c with no value following it,
// an oversized or unreadable script path, or a bare invocation with
// nothing statically visible to check (an interactive shell, or one
// genuinely reading from piped stdin). This is Command Policy's
// shell-invocation gate: the default for anything it cannot statically
// resolve is refuse, not allow (see docs/THREATS.md's "what is and is not
// statically inspected").
//
// Recognised options, matching real shells' own getopt-style parsing: -e
// -u -x -l -i -n -v -p -s -a -b -f -h -k -m -t (any combination, e.g. -euo
// pipefail), -o/-O/+o/+O <arg> (the arg is consumed as a separate word,
// whether given alone or as the last letter of a combined group), and the
// long forms --noprofile --norc --login --posix. -c may appear anywhere in
// a combined short-flag group (-xc, -euc) and always takes the next word
// as its string, matching shellCommandString's pre-CLA-62 behaviour for
// that shape.
func shellCommandString(args []string) (content string, refuse bool) {
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") {
			break
		}
		switch {
		case a == "-o" || a == "+o" || a == "-O" || a == "+O":
			if i+1 >= len(args) {
				return "", true
			}
			i += 2
		case a == "--noprofile" || a == "--norc" || a == "--login" || a == "--posix":
			i++
		case strings.HasPrefix(a, "--"):
			// An unrecognised long option: fail closed rather than guess.
			return "", true
		default:
			letters := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "+")
			if letters == "" {
				return "", true
			}
			if strings.ContainsRune(letters, 'c') {
				if i+1 >= len(args) {
					return "", true
				}
				return args[i+1], false
			}
			if !isKnownShortOpts(letters) {
				return "", true
			}
			last := letters[len(letters)-1]
			i++
			if last == 'o' || last == 'O' {
				if i >= len(args) {
					return "", true
				}
				i++
			}
		}
	}
	if i >= len(args) {
		// No -c, no script path: nothing statically visible to check (an
		// interactive shell, or one truly reading piped stdin).
		return "", true
	}
	return scriptFileContent(args[i])
}

// isKnownShortOpts reports whether every letter in a combined short-flag
// group (the "euo" of "-euo", the "x" of "-x") is one shellCommandString
// recognises as taking no argument of its own. "o"/"O" must be the last
// letter in the group, since its argument is the next argv word —
// matching a real shell's own getopt behaviour.
func isKnownShortOpts(letters string) bool {
	for j, r := range letters {
		switch r {
		case 'e', 'u', 'x', 'l', 'i', 'n', 'v', 'p', 's', 'a', 'b', 'f', 'h', 'k', 'm', 't':
			continue
		case 'o', 'O':
			return j == len(letters)-1
		default:
			return false
		}
	}
	return true
}

// scriptFileContent reads path as the shell script a bare `<shell>
// path...` invocation would run: refusing, rather than silently allowing
// unchecked, when path is not a readable regular file no larger than
// maxStaticScriptSize.
func scriptFileContent(path string) (content string, refuse bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxStaticScriptSize {
		return "", true
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", true
	}
	return string(raw), false
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
	// Leading assignments: VAR=$SECRET taints VAR; a plain string literal
	// (VAR=.env, no $ of its own) is remembered so a later bare $VAR can be
	// resolved back to it (resolveLiteral).
	i := 0
	for i < len(words) {
		m := assignment.FindStringSubmatch(words[i].raw)
		if m == nil {
			break
		}
		if ev.references(m[2]) != "" {
			ev.tainted[m[1]] = true
		} else if !strings.ContainsRune(m[2], '$') {
			ev.literals[m[1]] = m[2]
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
			resolved := ev.resolveLiteral(a.raw)
			if ev.underProtected(resolved) {
				return &Refusal{Rule: prog + " would print a Secret file", Advice: "pass the path to the tool that needs the file instead"}
			}
			if r := secretFileRefusal(prog, resolved); r != nil {
				return r
			}
		}
	case sourceBuiltins[prog]:
		for _, a := range args {
			if r := secretFileRefusal(prog, ev.resolveLiteral(a.raw)); r != nil {
				return r
			}
		}
	case shells[prog]:
		// Resolve what this shell invocation actually executes the same
		// way regardless of an attached heredoc, matching real shell
		// semantics: when a `-c STRING` or script-by-path argument is
		// given, THAT is what runs — an attached heredoc is just stdin
		// data for the invocation, irrelevant unless the -c string /
		// script itself chooses to read stdin, which can't be known
		// statically. shellCommandString is tried first, over a copy of
		// args with the heredoc placeholder word filtered out so it can
		// never be mistaken for -c's value or a script path; only when
		// that finds neither -c nor a script path (the shell would
		// otherwise read interactively from stdin) does the attached
		// heredoc's body become the executed script. Previously the
		// heredoc was checked first and, when present, evaluated
		// instead of a real -c/script-path argument alongside it — a
		// full, silent bypass of every rule below (CLA-62 review).
		raw := make([]string, 0, len(args))
		for _, a := range args {
			if !a.hasHeredoc {
				raw = append(raw, a.raw)
			}
		}
		content, refuse := shellCommandString(raw)
		if !refuse {
			if hasTraceFlag(raw) {
				return &Refusal{Rule: "shell tracing (-x) echoes expanded variables", Advice: "drop -x"}
			}
			return ev.shell(content, depth+1)
		}
		if hd, ok := heredocArg(args); ok {
			return ev.shell(hd.body, depth+1)
		}
		return &Refusal{
			Rule:   prog + "'s invocation shape can't be checked statically",
			Advice: `use -c "..." or a readable script file under 1 MiB (cpass reads and checks it) instead`,
		}
	}
	// Anything else: judge as an argv, so nested shells, env, printenv apply.
	argv := make([]string, len(rest))
	for i, w := range rest {
		argv[i] = w.raw
	}
	return ev.argv(argv, depth+1)
}

// references returns the first bound or tainted variable referenced in s,
// direct ($VAR/${VAR}) or indirect (${!x}, where x's own value — resolved
// through literals — names the variable actually being read).
func (ev *evaluator) references(s string) string {
	for _, m := range varRef.FindAllStringSubmatch(s, -1) {
		if _, ok := ev.bound[m[1]]; ok {
			return m[1]
		}
		if ev.tainted[m[1]] {
			return m[1]
		}
	}
	for _, m := range indirectVarRef.FindAllStringSubmatch(s, -1) {
		name, ok := ev.literals[m[1]]
		if !ok {
			continue
		}
		if _, ok := ev.bound[name]; ok {
			return name
		}
		if ev.tainted[name] {
			return name
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

// resolveLiteral returns the value a word resolves to when it is exactly
// one reference ($f or ${f}) to a variable earlier assigned a plain string
// literal in this same shell string (f=.env; cat "$f") — so
// secretFileRefusal and underProtected can judge the real filename, not
// the literal text "$f". Anything else (text around the reference, a
// bound/tainted Secret reference, no reference at all, an unknown
// variable) is returned unchanged.
func (ev *evaluator) resolveLiteral(s string) string {
	name, whole := wholeVarRef(s)
	if !whole {
		return s
	}
	if lit, ok := ev.literals[name]; ok {
		return lit
	}
	return s
}

// wholeVarRef reports whether s is exactly one variable reference ($NAME or
// ${NAME}) and nothing else, returning the variable's name.
func wholeVarRef(s string) (name string, whole bool) {
	if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") && len(s) > 3 {
		inner := s[2 : len(s)-1]
		if identRe.MatchString(inner) {
			return inner, true
		}
		return "", false
	}
	if strings.HasPrefix(s, "$") {
		inner := s[1:]
		if identRe.MatchString(inner) {
			return inner, true
		}
	}
	return "", false
}

// heredocInfo is the resolved body of a <<[-]DELIM redirection attached to
// a simple command.
type heredocInfo struct {
	body   string
	quoted bool
}

// heredocArg reports the first heredoc word among words, if any.
func heredocArg(words []word) (heredocInfo, bool) {
	for _, w := range words {
		if w.hasHeredoc {
			return heredocInfo{body: w.heredoc, quoted: w.heredocQuoted}, true
		}
	}
	return heredocInfo{}, false
}
