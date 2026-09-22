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
	// Cwd is the directory the command will actually run in, when a
	// caller knows one that can differ from this process's own working
	// directory — the MCP server's run_with_secrets tool passes its
	// caller-given cwd here, since that one long-lived process's own
	// directory never follows the Agent's. Left empty (as cpass run and
	// EvaluateHook both leave it, since for them the invoking process's
	// own directory already IS where the command runs), Evaluate falls
	// back to os.Getwd() itself.
	Cwd string
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
	// cwd is the directory the command actually runs in — in.Cwd when the
	// caller supplied one that can differ from this process's own (the
	// MCP server), otherwise the invoking process's own working directory
	// (os.Getwd(), which for cpass run and EvaluateHook already IS where
	// the command runs) — captured once here so a relative-looking
	// argument to a reader can be resolved against it (resolvePath) the
	// same way a real shell would resolve it, including after a literal
	// `cd DIR` tracked within one shell string (see the "cd" case in
	// simple). Neither source available (in.Cwd empty and os.Getwd
	// erroring — an unreadable/removed cwd) leaves this "", which
	// resolvePath treats as "nothing to resolve against" — the same
	// absolute-path-only behaviour underProtected already had.
	cwd := in.Cwd
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	ev := &evaluator{
		bound:     map[string]vault.BindingKind{},
		tainted:   map[string]bool{},
		literals:  map[string]string{},
		fds:       map[string]string{},
		protected: in.ProtectedDirs,
		cwd:       cwd,
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
	// cwd is this evaluator's current idea of the working directory —
	// the invoking process's real cwd, updated by a literal `cd DIR` seen
	// earlier in the same shell string (the "cd" case in simple) — used
	// by resolvePath to make a relative reader argument comparable against
	// an absolute ProtectedDirs entry
	// (command-policy:protecteddirs-relative-path-after-cd).
	cwd string
	// fds maps a file-descriptor key (a bare number, or "$name" for
	// bash's `exec {name}< target` allocated-descriptor form — see
	// split.go's fdBindPrefix/readFdAliasTarget) to the literal file path
	// a same-shell-string `exec N< target` bound it to, so a LATER
	// command's `<&N`/`<&$name` fd-alias redirection (word.fdAliasNum)
	// can be resolved back to the real path it reads
	// (command-policy:read-builtin-and-fd-redirection-bypass). Only a
	// resolvable, literal (no leftover "$") target populates this map —
	// same "resolve only what's statically knowable" default
	// ev.literals/ev.cwd already apply to a variable/cd target.
	fds map[string]string
}

func (ev *evaluator) underProtected(w string) bool {
	for _, d := range ev.protected {
		if d != "" && strings.HasPrefix(w, d+"/") {
			return true
		}
	}
	return false
}

// resolvePath resolves w against ev.cwd when w is a relative path, so
// underProtected's absolute-prefix check still recognises a live
// file-Binding referenced by a relative name — after a same-command `cd`
// into its run directory, or simply because the invoking process's own
// cwd already is (or is under) a ProtectedDirs entry. An already-absolute
// w, a flag-shaped w, or one this evaluator has no cwd to resolve against,
// is returned unchanged.
func (ev *evaluator) resolvePath(w string) string {
	if w == "" || ev.cwd == "" || filepath.IsAbs(w) || strings.HasPrefix(w, "-") {
		return w
	}
	return filepath.Join(ev.cwd, w)
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
		// read/mapfile/readarray: shell builtins that load a redirected
		// file's content into a variable (`read -r line < .env`,
		// `mapfile -t lines < .env`) rather than taking it as a plain
		// string argument to an external reader program — their file
		// operand arrives via the same `<` redirection-target word logic
		// CLA-61 already routes through matchesSecretFile/underProtected
		// for every other reader, so treating them as readers here is a
		// direct, low-risk extension: no new parsing needed
		// (command-policy:read-builtin-and-fd-redirection-bypass). A
		// flag-shaped argument (`-r`, `-t`) is already excluded by
		// matchesSecretFile's own leading-"-" check, same as for every
		// other reader.
		"read": true, "mapfile": true, "readarray": true,
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
			if ev.underProtected(ev.resolvePath(w)) {
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
	if r := readerWordRefusal(argv); r != nil {
		return r
	}
	return ev.shellWordRefusal(argv, depth)
}

// shellWordRefusal mirrors hookWalk's per-word SHELL-name fallback
// (internal/policy/hook.go) the same way readerWordRefusal above already
// mirrors hookWalk's per-word READER-name fallback: even when argv[0]
// isn't itself a shell, a shell name appearing anywhere else in argv —
// behind a wrapper neither `wrappers` nor `shells` enumerates, and which
// can never be exhaustively enumerated (chroot, unshare, ssh host,
// script -qc, setsid, systemd-run, nsenter, valgrind --, strace -f,
// docker exec, or any other passthrough shim) — is still a real shell
// invocation a real exec family call will make, and its own -c
// STRING/script-path content is still checkable text sitting right there
// in argv. Before this, Evaluate's per-word fallback covered only reader
// names, leaving a shell behind an unenumerated wrapper completely
// unchecked — a parity gap with hookWalk, whose own per-word loop checks
// shells[prog] in the very same pass as readers[prog]
// (command-policy:evaluate-shell-behind-unenumerated-wrapper-parity-gap).
// Mirrored exactly, including hookWalk's own lack of a printer exemption
// here (unlike readerWordRefusal/hookWalk's readers[prog] check, which
// both exempt echo/printf's own data arguments): a shell name genuinely
// invoked, not merely mentioned as data, is the shape this closes, and
// diverging from hookWalk's existing, already-shipped behavior in either
// direction would itself be a fresh parity gap.
func (ev *evaluator) shellWordRefusal(argv []string, depth int) error {
	for i := 1; i < len(argv); i++ {
		prog := base(argv[i])
		if !shells[prog] {
			continue
		}
		content, refuse := shellCommandString(argv[i+1:])
		if refuse {
			return &Refusal{
				Rule:   prog + "'s invocation shape can't be checked statically",
				Advice: `use -c "..." or a readable script file under 1 MiB (cpass reads and checks it) instead`,
			}
		}
		if hasTraceFlag(argv[i+1:]) {
			return &Refusal{Rule: "shell tracing (-x) echoes expanded variables", Advice: "drop -x"}
		}
		if err := ev.shell(content, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// readerWordRefusal mirrors hookWalk's per-word reader-name fallback
// (internal/policy/hook.go) for a flat argv with no shell involved: even
// when argv[0] isn't itself a reader, a reader name appearing anywhere
// else in argv — the tail of a wrapper neither `wrappers` nor `shells`
// enumerates, e.g. `find . -exec cat .env \;` — is still a real
// subprocess invocation a real exec family call (execvp inside -exec, in
// find's own case) will make, and its own file-argument words are still
// checkable text sitting right there in argv. Before this, Evaluate (the
// function cpass run and the MCP server actually gate real execution
// with) special-cased only the fixed `wrappers` map plus `timeout`,
// leaving every other wrapper completely unchecked — a parity gap with
// EvaluateHook's hookWalk, which already scans every word position for
// exactly this reason
// (command-policy:evaluate-missing-hook-per-word-wrapper-coverage).
// argv[0] itself is exempt when it is a pure-output printer
// (echo/printf/print): the remaining words are then data it prints, never
// programs it runs — the same exemption hookWalk's printerArg applies.
func readerWordRefusal(argv []string) *Refusal {
	if len(argv) == 0 || printers[base(argv[0])] {
		return nil
	}
	for i := 1; i < len(argv); i++ {
		prog := base(argv[i])
		if !readers[prog] {
			continue
		}
		for _, arg := range argv[i+1:] {
			if r := secretFileRefusal(prog, arg); r != nil {
				return r
			}
		}
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
// Recognised options, matching real shells' own getopt-style parsing (see
// shell.c's parse_shell_options for the real thing this mirrors): -e -u -x
// -l -i -n -v -p -s -a -b -f -h -k -m -t (any combination, e.g. -euo
// pipefail), -o/-O/+o/+O (each occurrence consumes the next not-yet-claimed
// argv word as its own option-name argument, wherever it falls in a
// combined group — -co, -oc, -euo pipefail and +co all consume exactly one
// word for the o/O), and the long forms --noprofile --norc --login
// --posix. -c may appear anywhere in a combined short-flag group (-xc,
// -euc, -co, -oc) and, unlike o/O, does not itself consume a word — a real
// shell only reads the pending command string once the *entire* run of
// option tokens ends, so it always names the first word after every
// flag's own argument(s) have been claimed, never "the next word after
// wherever c happened to sit" (see shellCommandString's doc comment and
// CLA-62's review fix: the previous combined-group handling returned the
// word immediately after 'c' the instant it saw the letter, so `-co
// pipefail 'cat .env'` read "pipefail" as the command string and the real
// command never got evaluated at all).
func shellCommandString(args []string) (content string, refuse bool) {
	i := 0
	cSeen := false
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
			i++
			// Walk this token's letters left to right: o/O each claim the
			// next unclaimed argv word right here (matching real getopt
			// behaviour, and matching every ordering this package has
			// live-verified against an actual shell: -co, -oc, +co, +oc,
			// -cO all consume exactly one word for the o/O regardless of
			// which side of 'c' it's on), c is only noted as seen — its
			// word, if any, is claimed once the whole run of option
			// tokens ends, below.
			for _, r := range letters {
				switch r {
				case 'e', 'u', 'x', 'l', 'i', 'n', 'v', 'p', 's', 'a', 'b', 'f', 'h', 'k', 'm', 't':
					// No argument of its own.
				case 'c':
					cSeen = true
				case 'o', 'O':
					if i >= len(args) {
						return "", true
					}
					i++
				default:
					// An unrecognised letter: fail closed rather than guess.
					return "", true
				}
			}
		}
	}
	if cSeen {
		if i >= len(args) {
			return "", true
		}
		return args[i], false
	}
	if i >= len(args) {
		// No -c, no script path: nothing statically visible to check (an
		// interactive shell, or one truly reading piped stdin).
		return "", true
	}
	return scriptFileContent(args[i])
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
	// CLA-61: an unquoted-delimiter heredoc body is parameter-expanded by
	// a real shell exactly like a double-quoted string before it ever
	// reaches the reading program's stdin, so a bound/tainted variable
	// referenced in it (`cat <<EOF
	// $STRIPE_LIVE
	// EOF`) resolves to the Secret's real value there precisely the way
	// `echo $STRIPE_LIVE` does — refused here regardless of which program
	// the heredoc is attached to, since a reading program given no file
	// operand generally does nothing but echo its stdin back out. A
	// quoted delimiter's body is never checked here: it is genuinely
	// inert data in a real shell, byte-for-byte, never expanded. (A shell
	// reading its own heredoc as a *script* — the shells[prog] case below
	// — is unaffected by this check finding nothing to say about it
	// either way: that path already re-parses the whole body as commands
	// and catches a reveal there on its own terms.)
	for _, w := range words {
		if w.hasHeredoc && !w.heredocQuoted {
			if v := ev.references(w.heredoc); v != "" {
				return &Refusal{
					Rule:   fmt.Sprintf("this command's heredoc body would print $%s", v),
					Advice: "pass the variable to the tool that needs it instead",
				}
			}
		}
	}
	// command-policy:read-builtin-and-fd-redirection-bypass — a `N<
	// target`/`{name}< target` redirection's target word (fdBindNum set,
	// see split.go's word doc comment) is recorded against its fd key
	// regardless of which command it's attached to (not only "exec"),
	// matching real shell semantics for the idiom this closes (`exec N<
	// target`, so a LATER command's `<&N` picks it back up) while
	// staying conservative rather than modeling per-command fd scoping
	// precisely: recording a few extra, unused fd keys for a redirection
	// that in real bash would only be scoped to its own command can only
	// make a LATER `<&N` resolve to a path that really was assigned to
	// that number at some point in this shell string, never to
	// something invented — the same "refuse/resolve rather than guess"
	// direction this package's other unresolved-dynamic-reference
	// defaults already favor. Only a resolvable, literal (no leftover
	// "$") target is recorded, exactly like ev.cwd's own cd-tracking.
	for _, w := range words {
		if w.fdBindNum != "" {
			if resolved := ev.resolveLiteral(w.raw); !strings.ContainsRune(resolved, '$') {
				ev.fds[w.fdBindNum] = ev.resolvePath(resolved)
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
	args := rest[1:]
	// command-policy:dynamic-command-name-not-resolved — the cheapest,
	// highest-value case: a whole variable reference ($x/${x}) naming the
	// command itself, where x was earlier assigned a plain string literal
	// (ev.literals, the same map resolveLiteral already reads for a
	// file-argument literal), is exactly what a real shell expands and
	// re-parses as the actual command line before running it — `x='cat
	// .env'; $x` really executes `cat .env`. Re-split and re-evaluate
	// that literal text (plus any words following $x, which a real shell
	// leaves as further arguments after $x's own word-splitting) as a
	// fresh command, the same way eval's argument already is below.
	// Command substitution ($(...)) and array ($x/${arr[@]}) forms need
	// the substitution's actual runtime *output*, which can't be known
	// statically, and remain a disclosed gap (docs/THREATS.md).
	if resolved := ev.resolveLiteral(rest[0].raw); resolved != rest[0].raw {
		parts := make([]string, 0, len(args)+1)
		parts = append(parts, resolved)
		for _, a := range args {
			parts = append(parts, a.raw)
		}
		return ev.shell(strings.Join(parts, " "), depth+1)
	}
	prog := base(rest[0].raw)
	switch {
	case prog == "cd":
		// Track a literal `cd DIR` target the same way a plain-string
		// variable assignment already is (ev.literals) — so a following
		// relative reader argument in this same shell string resolves
		// against it (resolvePath), closing
		// command-policy:protecteddirs-relative-path-after-cd's
		// `cd $RUNDIR && cat gcp-sa` shape. Only a single, resolvable
		// (no leftover "$", not flag-shaped) argument updates it; `cd`
		// with no argument, `cd -`, or a target this evaluator can't
		// resolve to a literal leaves ev.cwd unchanged rather than
		// guessing.
		if len(args) == 1 {
			if resolved := ev.resolveLiteral(args[0].raw); !strings.HasPrefix(resolved, "-") && !strings.ContainsRune(resolved, '$') {
				ev.cwd = ev.resolvePath(resolved)
			}
		}
		return nil
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
			// command-policy:read-builtin-and-fd-redirection-bypass: a
			// `<&N`/`<&$name` fd-alias word (raw=="", see split.go's
			// word doc comment) resolves through a same-shell-string
			// `exec N< target` bind (ev.fds) — the same treatment a
			// literal filename argument already gets below, just
			// reached through a fd number instead of a variable or a
			// literal path. An unresolvable key (a real, unrelated fd
			// this package never saw bound) falls through unchanged,
			// exactly like an unresolvable variable reference already
			// does.
			if path, ok := ev.resolveFDAlias(a); ok {
				if ev.underProtected(path) {
					return &Refusal{Rule: prog + " would print a Secret file", Advice: "pass the path to the tool that needs the file instead"}
				}
				if r := secretFileRefusal(prog, path); r != nil {
					return r
				}
				continue
			}
			if v := ev.referencesFile(a.raw); v != "" {
				return &Refusal{Rule: fmt.Sprintf("%s would print the file behind $%s", prog, v), Advice: "pass the path to the tool that needs the file instead"}
			}
			// command-policy:reader-here-string-reveal-bypass: a reader
			// given a bound/tainted variable with no matching file
			// operand — a here-string (`cat <<< $STRIPE_LIVE`) is the
			// live shape, since <<<'s target flows through this same
			// ordinary-word/argument logic — is functionally "cat used
			// as echo" and reveals the value on stdout exactly like
			// `echo $STRIPE_LIVE` does; refused the same way a printer
			// argument already is above.
			if v := ev.references(a.raw); v != "" {
				return &Refusal{Rule: fmt.Sprintf("%s would print $%s", prog, v), Advice: "pass the variable to the tool that needs it instead"}
			}
			resolved := ev.resolveLiteral(a.raw)
			if ev.underProtected(ev.resolvePath(resolved)) {
				return &Refusal{Rule: prog + " would print a Secret file", Advice: "pass the path to the tool that needs the file instead"}
			}
			if r := secretFileRefusal(prog, resolved); r != nil {
				return r
			}
			// command-policy:shell-glob-expansion-hides-filename: an
			// argument shaped like a shell glob (`.en?`, `.e*`) is
			// additionally resolved against this evaluator's cwd the
			// way a real shell's own filename globbing would expand
			// it, since matchesSecretFile's plain basename match above
			// only ever compares literal text and a glob pattern's own
			// literal spelling never itself looks like ".env".
			if r := ev.secretFileGlobRefusal(prog, resolved); r != nil {
				return r
			}
		}
	case sourceBuiltins[prog]:
		for _, a := range args {
			if path, ok := ev.resolveFDAlias(a); ok {
				if r := secretFileRefusal(prog, path); r != nil {
					return r
				}
				continue
			}
			resolved := ev.resolveLiteral(a.raw)
			if r := secretFileRefusal(prog, resolved); r != nil {
				return r
			}
			if r := ev.secretFileGlobRefusal(prog, resolved); r != nil {
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

// resolveFDAlias returns the literal file path a `<&N`/`<&$name` word
// (fdAliasNum set, raw=="" — see split.go's word doc comment) resolves
// to, via a same-shell-string `exec N< target`/`exec {name}< target`
// bind recorded in ev.fds — or ok==false when w isn't such a word at
// all, or its fd key isn't tracked (an ordinary, unrelated real file
// descriptor, or a dynamic value this package can't resolve statically),
// matching the same "leave it alone rather than guess" default every
// other dynamic reference in this package already has
// (command-policy:read-builtin-and-fd-redirection-bypass).
func (ev *evaluator) resolveFDAlias(w word) (path string, ok bool) {
	if w.fdAliasNum == "" {
		return "", false
	}
	path, ok = ev.fds[w.fdAliasNum]
	return path, ok
}

// secretFileGlobRefusal reports whether arg — already checked against
// secretFileGlobs by matchesSecretFile's plain literal-basename match —
// additionally contains a shell glob metacharacter (*, ?, [) that, once
// expanded against this evaluator's own cwd the way a real shell's
// filename globbing would expand it before the reading program ever
// starts, resolves to a Secret-bearing file that actually exists there:
// `cat .en?`/`cat .e*` expanding to a real .env is the load-bearing case
// (command-policy:shell-glob-expansion-hides-filename) — unlike this
// package's other checks, which are purely textual, this one is
// necessarily filesystem-dependent, but that dependency is exactly what
// is guaranteed to hold in precisely the scenario Command Policy exists
// to defend: a real .env sitting in the project directory. An argument
// with no glob metacharacter at all is untouched (nil, cheaply, before
// any I/O). When this evaluator has no usable cwd, or the glob itself
// can't be evaluated, this fails closed (refuses) rather than silently
// letting an unresolvable glob pattern through unchecked — this
// package's existing default for any other shape it cannot statically
// resolve. A glob that resolves to nothing dangerous (no match at all,
// or matches that aren't Secret-bearing) is allowed, exactly like an
// ordinary non-glob filename that isn't one.
func (ev *evaluator) secretFileGlobRefusal(prog, arg string) *Refusal {
	if !strings.ContainsAny(arg, "*?[") || strings.HasPrefix(arg, "-") {
		return nil
	}
	unresolvable := &Refusal{
		Rule:   prog + "'s glob argument " + arg + " can't be checked statically",
		Advice: "reference the file by its literal name instead of a glob pattern",
	}
	if ev.cwd == "" {
		return unresolvable
	}
	pattern := arg
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(ev.cwd, pattern)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return unresolvable
	}
	for _, m := range matches {
		if r := secretFileRefusal(prog, m); r != nil {
			return r
		}
	}
	return nil
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
