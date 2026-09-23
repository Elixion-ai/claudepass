// Package policy statically refuses the well-known ways a command an
// Agent wants to run would reveal a bound Secret or read a Secret-bearing
// file directly, modeling real shell syntax as far as that stays precise,
// and fails closed — refuses, not silently runs unchecked — on a
// shell-invocation shape it cannot parse (see docs/adr/0013). It is not,
// and does not try to be, a complete decision procedure for arbitrary
// shell: a command can compute what it does at run time (an interpreter's
// own -c/-e string, eval of a dynamically constructed string, a program
// that opens a file by a name this package never modeled as file-shaped,
// an unenumerated wrapper), and docs/THREATS.md's own numbered list is
// the honest, standing account of exactly which such shapes this package
// does not attempt. The same evaluator (Evaluate) serves cpass run, the
// MCP server's run_with_secrets/capture tools, and — via EvaluateHook,
// which applies Evaluate's rules plus one more before any value exists to
// bind — the Claude Code PreToolUse hook, so these rules are the same
// everywhere with the small number of disclosed exceptions
// docs/THREATS.md's own list states precisely (the hook's own `cpass add`
// inline-value check, the argv[0] exclusion from the raw-literal scan,
// the hook-only printenv allowlist for well-known non-secret variable
// names (CLA-102), and the hook-only `set -x`/shell-tracing allowlist
// (CLA-103)): consult that list rather than assuming this comment
// enumerates them, since a fix can close one without this file ever
// changing.
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
	// EnvAllowlist opts a small, fixed set of well-known non-secret
	// variable names (hookEnvAllowlist, internal/policy/hook.go) out of
	// the `printenv` reveal refusal below — set only by EvaluateHook
	// (CLA-102). The hook has no Bound-variable knowledge at all, so
	// without this it must refuse ANY `printenv NAME` conservatively,
	// even an utterly ordinary `printenv PATH`/`printenv HOME` lookup,
	// which is needless friction for everyday debugging. cpass run and
	// the MCP server's own Evaluate calls never set this: real execution
	// DOES have real Bound Secret values sitting in the same process
	// environment as PATH/HOME, so this package keeps its stricter,
	// allowlist-free printenv refusal there rather than assuming a name
	// is safe just because it looks like an ordinary one.
	EnvAllowlist bool
	// TraceAllowlist opts `set -x`/`set -o xtrace`/a combined short-flag
	// group containing `x` (`-euxo pipefail`, ...) out of the "set -x
	// echoes expanded variables" refusal below — set only by
	// EvaluateHook (CLA-103), the same hook-only shape EnvAllowlist
	// above already is. At the hook layer nothing is ever Bound yet (see
	// EnvAllowlist's own doc comment: the hook judges a raw Bash call
	// before cpass has parsed anything, let alone resolved a Handle), so
	// tracing a debugging script there can only ever echo the Agent's
	// own already-visible commands and its own process environment,
	// never a Vault Secret — refusing it is needless friction for the
	// extremely common `set -euxo pipefail` script preamble. cpass run
	// and the MCP server's own Evaluate calls never set this: real
	// execution DOES have real Bound Secret values sitting in the
	// process a traced script's own `+ echo $STRIPE_LIVE`-style line
	// would echo, so this package keeps its stricter, allowlist-free
	// refusal there. A bare `set` with no arguments is unaffected either
	// way — it prints every variable unconditionally, which has nothing
	// to do with tracing specifically and stays refused everywhere.
	TraceAllowlist bool
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
		bound:          map[string]vault.BindingKind{},
		tainted:        map[string]bool{},
		literals:       map[string]string{},
		fds:            map[string]string{},
		written:        map[string]string{},
		protected:      in.ProtectedDirs,
		cwd:            cwd,
		envAllowlist:   in.EnvAllowlist,
		traceAllowlist: in.TraceAllowlist,
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
	// written maps a literal file path (resolved through ev.resolveLiteral,
	// the same as every other file-argument path in this package) to the
	// content CLA-103's write-then-run tracking recorded for it from an
	// earlier `cat > PATH <<DELIM`/`cat <<DELIM > PATH`/`cat >> PATH
	// <<DELIM`/`tee [-a] PATH <<DELIM` in THIS SAME shell string
	// (heredocToFileWrite, populated by ev.simple) — so a LATER `<shell>
	// PATH` invocation of the identical literal path can resolve to that
	// body (ev.shellScriptContent) instead of failing the on-disk read
	// that hasn't happened yet, since this whole evaluation runs BEFORE
	// either write or run has actually executed. Cleared entirely the
	// instant a `cd` is seen anywhere in this shell string (see the "cd"
	// case in simple) — deliberately blanket/conservative rather than
	// reasoning precisely about which entries a particular cd target
	// would or wouldn't invalidate, matching this package's existing
	// "refuse/resolve rather than guess" default: a path that differs
	// from the one actually executed even trivially (a `./` prefix, a
	// different quoting) is a different map key and so is never matched,
	// falling through to this package's ordinary fail-closed refusal
	// unchanged.
	written map[string]string
	// envAllowlist mirrors Input.EnvAllowlist (see its own doc comment):
	// true only for the evaluator EvaluateHook builds, never for a real
	// cpass run / MCP server invocation.
	envAllowlist bool
	// traceAllowlist mirrors Input.TraceAllowlist (see its own doc
	// comment): true only for the evaluator EvaluateHook builds, never
	// for a real cpass run / MCP server invocation.
	traceAllowlist bool
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

// maxDepthRefusal is returned once a command's own nested structure
// (shells inside shells, command substitutions, wrapped `cpass run`
// invocations, ...) exceeds maxDepth levels — refusing, not silently
// allowing, so an adversarially over-nested command can't evade every
// rule above by nesting past what this package will keep recursing
// into. maxDepth (8) is generous enough that no legitimate command in
// this package's own test corpus or the false-positive A/B harness
// comes remotely close to it; a real command that genuinely needs more
// is vanishingly rare and, unlike every other refusal in this package,
// has no narrower fix available short of raising the constant.
var maxDepthRefusal = &Refusal{
	Rule:   "this command nests more than 8 shells/substitutions deep",
	Advice: "simplify the command so its structure can be checked statically",
}

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
	// readBuiltins are the readers entries that are shell BUILTINS whose
	// own positional words are destination variable/array names, never a
	// file path — read/mapfile/readarray's only possible file operand is
	// a `< target` redirection word (word.redirTarget) or a same-
	// shell-string fd alias (resolveFDAlias), unlike every other
	// `readers` entry (a real reader program), whose ordinary positional
	// words genuinely are file arguments. Checking a positional word of
	// one of these three against secretFileGlobs the same way wrongly
	// refuses e.g. `read -r id_rsa_output` or `mapfile -t id_rsa_lines`
	// — no file is read at all, "id_rsa_output"/"id_rsa_lines" are only
	// ever variable/array names, never the id_rsa* SSH key file itself
	// (command-policy:read-builtin-destination-name-not-a-filename).
	readBuiltins = map[string]bool{"read": true, "mapfile": true, "readarray": true}
	procEnviron  = regexp.MustCompile(`/proc/(self|\$\$|[0-9]+|[a-z]*\$[A-Za-z_{]*[}]?)/environ`)
	varRef       = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)`)
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
// server, and — via EvaluateHook — the PreToolUse hook) refuses the
// well-known, statically recognizable ways a command would read one
// directly: doing so bypasses the Vault, and the value would land
// straight in the Agent's Context. Matched with filepath.Match against
// the basename of each argument, so a path like "$HOME/.env" is still
// caught — but this is necessarily a list of known patterns (a reader
// program, a source builtin, a redirection, a resolvable variable or fd
// alias, a well-formed glob expansion), not a sandbox: a program that
// opens the file itself, through an argument shape this package doesn't
// model as file-like, is not caught this way (docs/THREATS.md).
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

// patternTakingReaders are the `readers` entries whose CLI convention
// puts a PATTERN/FILTER/SCRIPT — never a filename — at the first
// positional argument position: grep/egrep/fgrep's own regex, sed's
// `s/.../.../` script, awk's program, jq/yq's filter. Checking that
// argument against secretFileGlobs the same way a genuine filename
// argument is checked conflates "the text this reader is searching FOR"
// with "the file it would read" — e.g. `git grep -n '\.env\*'
// internal/policy` refuses because the PATTERN `\.env\*` happens to
// de-escape to literal text matching the `.env*` glob, even though
// internal/policy (the real, ordinary directory argument) is what grep
// actually reads (command-policy:reader-pattern-argument-not-a-
// filename).
var patternTakingReaders = map[string]bool{
	"grep": true, "egrep": true, "fgrep": true,
	"sed": true, "awk": true, "jq": true, "yq": true,
}

// readerPatternIndex returns the index within args (the words following
// a patternTakingReaders program name) that is that reader's own
// implicit PATTERN/FILTER/SCRIPT positional — exempt from every
// filename-style check a genuine file argument gets — or -1 when prog
// isn't one of those readers, no non-flag word exists to be it, or the
// first non-flag word found is actually the VALUE of a file-consuming
// flag (`-f`/`--file`: grep/awk's own pattern-file/program-file, sed's
// own script-file), which genuinely is a file argument and so must NOT
// be exempted the way the implicit bare-positional pattern is
// (command-policy:reader-pattern-argument-not-a-filename). Only the
// first candidate is ever exempt — every later positional is a real
// file argument, exactly as before.
func readerPatternIndex(prog string, args []string) int {
	if !patternTakingReaders[prog] {
		return -1
	}
	fileFlag := false
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			fileFlag = a == "-f" || a == "--file"
			continue
		}
		if fileFlag {
			return -1
		}
		return i
	}
	return -1
}

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
	if len(argv) == 0 {
		return nil
	}
	if depth > maxDepth {
		return maxDepthRefusal
	}
	for _, w := range argv {
		if procEnviron.MatchString(w) {
			return &Refusal{Rule: "reads the process environment file", Advice: "use the variable in a command instead of dumping it"}
		}
	}
	prog := base(argv[0])
	// read/mapfile/readarray never reach this loop meaningfully: a
	// literal exec-style argv (no shell string was ever parsed) has no
	// redirection syntax at all, so none of their own words could ever
	// be a `< target` file operand here — and they are shell builtins
	// besides, never a real argv[0] any exec family call would actually
	// invoke (command-policy:read-builtin-destination-name-not-a-
	// filename).
	if readers[prog] && !readBuiltins[prog] {
		patIdx := readerPatternIndex(prog, argv[1:])
		for k, w := range argv[1:] {
			// command-policy:reader-pattern-argument-not-a-filename:
			// grep/sed/awk/jq/yq's own PATTERN/FILTER/SCRIPT argument
			// (see readerPatternIndex) is never a filename.
			if k == patIdx {
				continue
			}
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
		// CLA-102: at the hook layer only (ev.envAllowlist), printenv
		// naming exclusively well-known, non-secret variables (PATH,
		// HOME, ...) is not a reveal worth blocking everyday debugging
		// over — see hookEnvAllowlist (hook.go) and Input.EnvAllowlist's
		// own doc comment for why this is scoped to the hook and no
		// further.
		if prog == "printenv" && ev.envAllowlist && printenvAllowlisted(argv[1:]) {
			return nil
		}
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
		content, ok, refusal := ev.shellScriptContent(argv[1:])
		if refusal != nil {
			return refusal
		}
		if !ok {
			return &Refusal{
				Rule:   prog + "'s invocation shape can't be checked statically",
				Advice: `use -c "..." or a readable script file under 1 MiB (cpass reads and checks it) instead`,
			}
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
		content, ok, refusal := ev.shellScriptContent(argv[i+1:])
		if refusal != nil {
			return refusal
		}
		if !ok {
			return &Refusal{
				Rule:   prog + "'s invocation shape can't be checked statically",
				Advice: `use -c "..." or a readable script file under 1 MiB (cpass reads and checks it) instead`,
			}
		}
		if err := ev.shell(content, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// coincidentalReaderSubcommands enumerates the specific, known {multi-
// level CLI, subcommand path} pairs whose own subcommand text happens to
// share a name with a `readers` entry without genuinely invoking (or
// even resembling) the real reader program of that name: the AWS CLI's
// own `aws logs tail` (streams remote CloudWatch log events; "tail" is
// AWS's own subcommand, not tail(1)) and `aws s3 cp` (AWS's own S3 copy
// operation, not cp(1)); kubectl's and docker's own `cp` subcommand
// (copies to/from a container, not a local read via cp(1)). Only a
// subcommand that is itself a `readers` name belongs here — the callers
// consult this list only at a word that already matched `readers`. This list
// is deliberately small and specific, not a general "does this word look
// like a subcommand" heuristic: readerWordRefusal/hookWalk below match a
// path here only by its EXACT, contiguous position starting right after
// the CLI's own program name (isCoincidentalReaderSubcommand), so it can
// only ever narrow detection for the precise shapes named here, never
// for a reader name appearing anywhere else — including behind a real
// wrapper this package doesn't otherwise enumerate (`docker exec`,
// `chroot`, `strace -f`, `setsid`, `unshare`, `stdbuf`, ...), which is
// exactly the class CLA-101's own trigger-word narrowing wrongly swept
// in along with these coincidental subcommands (CLA-101 review). Add to
// this list only a specific, verified {CLI, subcommand path} pair that
// is genuinely not a local file read — never a whole wrapper program or
// a broader pattern, which would silently reopen that same regression.
//
// DISCLOSED, PRE-EXISTING EDGE this exemption shares with CLA-101's own
// trigger-word version of it (not a new gap this fix introduces): the
// `cp` entries are direction-blind. `kubectl cp`/`docker cp` copy in
// either direction (`kubectl cp LOCAL pod:PATH` uploads and genuinely
// reads LOCAL off disk; `kubectl cp pod:PATH LOCAL` downloads and writes
// LOCAL instead), and this exemption skips the secretFileGlobs check for
// every argument once the subcommand path matches, in either direction —
// so `kubectl cp .env mypod:/root/.env`, a genuine local read, is no
// longer caught either, the same as it wasn't under CLA-101's own
// trigger-word gate (`kubectl` is neither a wrapper nor an exec-style
// flag there either). Telling "LOCAL argument" from "container:PATH
// argument" precisely enough to re-check only the genuinely local one
// would mean modeling each CLI's own copy-argument syntax, the same
// unbounded per-tool task docs/THREATS.md item 16 already declines
// generally; Redaction and `cpass import` remain the enforced boundary
// for this narrower shape, exactly as for the disclosed edges around it.
var coincidentalReaderSubcommands = map[string][][]string{
	"aws":     {{"logs", "tail"}, {"s3", "cp"}},
	"kubectl": {{"cp"}},
	"docker":  {{"cp"}},
}

// isCoincidentalReaderSubcommand reports whether the reader-name word at
// index i — wordAt(i) returning its raw text, already known by the
// caller to match a `readers` entry — is actually one of
// coincidentalReaderSubcommands' own known false-positive shapes rather
// than a genuine reader-program invocation. cmdStart is the index of the
// enclosing command's own program name (position 0 for a flat argv;
// commandStartIndex's result — position 0, or the first word after a
// leading run of VAR=value assignments — for a shell word list), and the
// words immediately following it up to and including i must match one
// of that CLI's own listed subcommand paths exactly, word for word, with
// nothing else in between: `aws --profile x logs tail ...` or `find .
// -exec aws logs tail .env \;` do NOT match (the path isn't contiguous
// from cmdStart, or cmdStart isn't the reader word's own enclosing
// command at all), so this stays a narrow exemption for the literal,
// reported shapes rather than a broad heuristic that could itself hide a
// real read (CLA-101 review).
func isCoincidentalReaderSubcommand(wordAt func(int) string, cmdStart, i int) bool {
	paths, ok := coincidentalReaderSubcommands[base(wordAt(cmdStart))]
	if !ok {
		return false
	}
	for _, path := range paths {
		if len(path) == 0 || cmdStart+len(path) != i {
			continue
		}
		match := true
		for k, seg := range path {
			if wordAt(cmdStart+1+k) != seg {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// readerWordRefusal mirrors hookWalk's per-word reader-name fallback
// (internal/policy/hook.go) for a flat argv with no shell involved: even
// when argv[0] isn't itself a reader, a reader name appearing anywhere
// else in argv — the tail of a wrapper neither `wrappers` nor `shells`
// enumerates, e.g. `find . -exec cat .env \;`, `docker exec c cat .env`,
// `chroot / cat .env`, `strace -f cat .env`, `setsid cat .env`, `unshare
// cat .env`, `stdbuf -oL cat .env`, or a bare `xargs`'s own first
// argument, e.g. `xargs cat < .env` — is still a real subprocess
// invocation a real exec family call will make, and its own
// file-argument words are still checkable text sitting right there in
// argv. Before CLA-99, Evaluate (the function cpass run and the MCP
// server actually gate real execution with) special-cased only the
// fixed `wrappers` map plus `timeout`, leaving every other wrapper
// completely unchecked — a parity gap with EvaluateHook's hookWalk,
// which already scanned every word position for exactly this reason
// (command-policy:evaluate-missing-hook-per-word-wrapper-coverage).
// argv[0] itself is exempt when it is a pure-output printer
// (echo/printf/print): the remaining words are then data it prints, never
// programs it runs — the same exemption hookWalk's printerArg applies.
//
// CLA-101 narrowed this from "any word position at all" to "only right
// after a known trigger word (a wrapper, an exec-style flag, xargs, or
// --)", closing the multi-level-CLI-subcommand false positive
// (`aws logs tail`, `kubectl cp`) this ticket names — but, as CLA-101's
// own review found, that also silently dropped every OTHER wrapper name
// this package doesn't happen to enumerate (`docker exec`, `chroot`,
// `strace`, `setsid`, `unshare`, `stdbuf`, and any other passthrough
// shim), which is exactly the class this fallback exists to catch in
// the first place — a substantial, undisclosed reduction of Command
// Policy's primary enforcement path, not a narrower version of the
// ticket's own disclosed trade-off. The review's fix restores the
// original "any word position" scan and instead excludes only the
// specific, small set of known coincidental {CLI, subcommand} pairs
// (coincidentalReaderSubcommands/isCoincidentalReaderSubcommand above) —
// a reader name anywhere else, trigger word or not, is still caught,
// exactly as it was before CLA-101.
//
// This also restores catching a multi-level CLI subcommand that
// genuinely DOES read a local file the way a real reader would (`git
// grep PATTERN .env`) as a side effect — CLA-101's own narrowing had
// disclosed losing that as an accepted, unavoidable cost of requiring a
// trigger word; it isn't unavoidable once the fix is a specific denylist
// instead, and refusing a command that really would read the file is
// correct, not a new false positive.
func readerWordRefusal(argv []string) *Refusal {
	if len(argv) == 0 || printers[base(argv[0])] {
		return nil
	}
	wordAt := func(k int) string {
		if k < 0 || k >= len(argv) {
			return ""
		}
		return argv[k]
	}
	for i := 1; i < len(argv); i++ {
		prog := base(argv[i])
		if !readers[prog] || readBuiltins[prog] {
			continue
		}
		if isCoincidentalReaderSubcommand(wordAt, 0, i) {
			continue
		}
		patIdx := readerPatternIndex(prog, argv[i+1:])
		for k, arg := range argv[i+1:] {
			// command-policy:reader-pattern-argument-not-a-filename:
			// grep/sed/awk/jq/yq's own PATTERN/FILTER/SCRIPT argument
			// (see readerPatternIndex) is never a filename — this is
			// what keeps `git grep -n '\.env\*' internal/policy` from
			// refusing on its own search PATTERN (which happens to
			// de-escape to literal text matching a secretFileGlobs
			// entry) while internal/policy, the real directory grep
			// reads, is untouched.
			if k == patIdx {
				continue
			}
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
// scriptPath, whenever this resolved to a script-by-path argument at all
// (whether or not its on-disk content could actually be read), is that
// argument's own literal text — "" for the -c STRING form, which never
// names a path. A caller with CLA-103's write-then-run tracking
// (evaluator.shellScriptContent/hookResolveScript) uses this to resolve a
// same-shell-string heredoc-to-file write before falling back to refuse
// on the on-disk read failure alone; a caller with no such tracking
// simply ignores it, exactly as before this return value existed.
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
func shellCommandString(args []string) (content string, scriptPath string, refuse bool) {
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
			return "", "", true
		default:
			letters := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "+")
			if letters == "" {
				return "", "", true
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
						return "", "", true
					}
					i++
				default:
					// An unrecognised letter: fail closed rather than guess.
					return "", "", true
				}
			}
		}
	}
	if cSeen {
		if i >= len(args) {
			return "", "", true
		}
		return args[i], "", false
	}
	if i >= len(args) {
		// No -c, no script path: nothing statically visible to check (an
		// interactive shell, or one truly reading piped stdin).
		return "", "", true
	}
	content, refuse = scriptFileContent(args[i])
	return content, args[i], refuse
}

// scriptFileContent reads path as the shell script a bare `<shell>
// path...` invocation would run: refusing, rather than silently allowing
// unchecked, when path is not a readable regular file no larger than
// maxStaticScriptSize. A leading `~/` or a bare `~` is expanded against
// $HOME first, the same way a real shell's own tilde expansion resolves
// it before ever handing the word to os.Stat — needed for this to find a
// real script named by a resolved variable
// (command-policy:shell-script-path-literal-variable's own common
// spelling, `G=~/bin/deploy.sh; bash $G`), since Go's os.Stat, unlike a
// shell, never expands `~` on its own. `~user/...` (a specific OTHER
// user's home) is left unexpanded — a shape this package doesn't attempt
// to resolve, matching its existing "don't guess" default; that leaves
// the path looking for a literal "~user"-named entry, so it fails
// os.Stat and falls to the ordinary unresolvable-shape refusal below,
// same as always.
func scriptFileContent(path string) (content string, refuse bool) {
	path = expandHome(path)
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

// expandHome expands a leading `~` (the whole path) or `~/...` to
// os.UserHomeDir(), the same narrow, common case a real shell's own
// tilde expansion covers for an unquoted leading `~`. Anything else
// (`~user/...`, an error reading $HOME, no leading `~` at all) is
// returned unchanged.
func expandHome(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, path[2:])
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

// heredocToFileWrite recognizes the write half of a write-then-run pattern
// within one simple command (CLA-103) — `cat > PATH <<DELIM`, `cat <<DELIM
// > PATH` (splitCommands always appends the heredoc word last regardless
// of which came first on the line, so both spellings tokenize identically
// — see word.outRedirTarget's own doc comment), `cat >> PATH <<DELIM`
// (append), or `tee [-a|--append] PATH <<DELIM` — returning the literal
// path written, the heredoc body that becomes its new content, and
// whether this is an append (so the caller prepends PATH's existing
// on-disk content, matching what a real `>>`/`tee -a` actually produces)
// rather than a truncating write. ok is false for anything else at all —
// no heredoc attached, more than one candidate target word, a real read
// argument alongside the redirect (`cat existing.txt > p <<D`, genuinely
// a different shape), or any other program or flag this narrow, exact
// list doesn't name — and the caller keeps its existing fail-closed
// refusal unchanged in that case, exactly as before this function
// existed: this is deliberately a small, exact denylist of known write
// shapes, not a guess at what "looks like" one.
func heredocToFileWrite(words []word) (path, body string, appendMode bool, ok bool) {
	if len(words) == 0 {
		return "", "", false, false
	}
	hd, hasHD := heredocArg(words)
	if !hasHD {
		return "", "", false, false
	}
	switch base(words[0].raw) {
	case "cat":
		var target *word
		for i := 1; i < len(words); i++ {
			w := &words[i]
			if w.hasHeredoc {
				continue
			}
			if !w.outRedirTarget || target != nil {
				// Anything that isn't the redirect's own target — a real
				// read argument, a flag, a second target — is not this
				// exact shape.
				return "", "", false, false
			}
			target = w
		}
		if target == nil {
			return "", "", false, false
		}
		return target.raw, hd.body, target.outRedirAppend, true
	case "tee":
		var target *word
		for i := 1; i < len(words); i++ {
			w := &words[i]
			if w.hasHeredoc {
				continue
			}
			if w.raw == "-a" || w.raw == "--append" {
				appendMode = true
				continue
			}
			if target != nil {
				return "", "", false, false
			}
			target = w
		}
		if target == nil {
			return "", "", false, false
		}
		return target.raw, hd.body, appendMode, true
	}
	return "", "", false, false
}

// nonRedirectWriters are argv[0] program names (after skipCommandPrefix)
// that overwrite a destination path named as a plain positional argument
// rather than through a `>`/`>>` shell redirection target word — cp, mv,
// and a bare `tee` invocation with no attached heredoc (heredocToFileWrite's
// own tee shape above requires one) are the three ordinary, widely-used
// ones. Modeling precisely which of cp/mv's own positional arguments is
// the destination (a trailing target directory, multiple sources, cp/mv's
// own -t/--target-directory flag, ...) is the same unbounded per-tool task
// docs/THREATS.md's own kubectl-cp/docker-cp direction-blind edge already
// declines generally, so instead — matching evaluator.written's own stated
// preference for conservative-over-precise, the same one the `cd` safety
// valve already uses — invalidateOverwrittenWrites below treats ANY
// invocation of one of these three (that heredocToFileWrite itself didn't
// just authoritatively record) as untrackable and blanket-clears every
// pending write-then-run candidate, rather than guessing which specific
// entry it would or wouldn't overwrite.
var nonRedirectWriters = map[string]bool{"cp": true, "mv": true, "tee": true}

// invalidateOverwrittenWrites drops a stale written[path] entry (CLA-103
// review finding) whenever THIS simple command (words, starting at the
// command's own program name — the same slice ev.simple's "rest"/
// hookWalk's "words[j:]" already pass to heredocToFileWrite) writes to a
// tracked path through any shape OTHER than the one heredocToFileWrite
// itself just recorded as recordedPath (the resolved literal path
// heredocToFileWrite authoritatively recorded new content for from this
// same command — "" when this command didn't match one of its four exact
// shapes at all). resolve resolves a word's raw text through the same
// plain-string-literal tracking (ev.resolveLiteral / resolveLiteralIn)
// every other file-argument path in this package already goes through.
//
// Two shapes are recognised:
//
//   - any word tagged word.outRedirTarget — the target of a `>`/`>>`
//     redirection on ANY program (`echo x > t.sh`, `sed ... >> t.sh`,
//     `cat > t.sh` with no heredoc attached at all) — tagged generically
//     by splitCommands for every output redirection, not only
//     heredocToFileWrite's own narrow cat/tee-with-heredoc match, but
//     never previously consulted outside it. Its resolved literal path is
//     deleted from written unless it is exactly recordedPath, which must
//     survive since it is the very entry heredocToFileWrite just set.
//   - a bare invocation of a nonRedirectWriters program (cp, mv, or tee
//     with no heredoc) that heredocToFileWrite didn't just authoritatively
//     record (recordedPath == "") — blanket-clears every pending entry
//     (see nonRedirectWriters' own doc comment for why blanket rather
//     than precise).
//
// Without this, a benign heredoc write recorded earlier in the same shell
// string stayed in written and went on to certify a LATER script-by-path
// run of that identical path even after this later, unrecognized write
// had silently replaced its real on-disk content with something never
// checked at all — the exact regression this closes. A `cd` anywhere
// already blanket-clears the whole map (the check just above this
// function's own call site in both ev.simple and hookWalk); this only
// ever narrows an entry (or, for a nonRedirectWriters program, the whole
// map) further — it never restores one a `cd` already dropped.
func invalidateOverwrittenWrites(words []word, written map[string]string, recordedPath string, resolve func(string) string) {
	if len(words) == 0 {
		return
	}
	if cmd := skipCommandPrefix(words, 0); recordedPath == "" && cmd < len(words) && nonRedirectWriters[base(words[cmd].raw)] {
		for k := range written {
			delete(written, k)
		}
		return
	}
	for i := range words {
		w := &words[i]
		if !w.outRedirTarget {
			continue
		}
		resolved := resolve(w.raw)
		if resolved == recordedPath {
			continue
		}
		delete(written, resolved)
	}
}

// shellScriptContent resolves what a shell invocation whose already-
// flattened, resolveLiteral'd flags/args are raw statically executes:
// shellCommandString's own -c STRING / on-disk script-by-path result when
// that succeeds, or — when a script-by-path argument was named but isn't
// (yet) readable from disk — the body CLA-103's write-then-run tracking
// (ev.written) recorded for that identical literal path earlier in this
// same shell string. ok is false for every other unresolvable shape (an
// interactive/piped-stdin invocation, an unrecognised flag, or a
// script-by-path argument neither on disk nor in ev.written), so the
// caller falls back to its own heredoc-body/final-refusal handling
// exactly as it did before this existed. refusal, when non-nil, is a
// trace-flag refusal (raw itself carries -x/xtrace on the shell
// invocation, e.g. `bash -x script.sh`) — checked here, once, rather than
// once per caller, since it applies identically regardless of whether the
// resolved content came from disk or from ev.written.
//
// The four ev.simple/ev.argv/shellWordRefusal/shellWordRefusalWords call
// sites that used to each repeat "shellCommandString, then hasTraceFlag,
// then a heredoc fallback" now all share this one resolution step instead
// of duplicating the written-map fallback four times over.
func (ev *evaluator) shellScriptContent(raw []string) (content string, ok bool, refusal *Refusal) {
	content, scriptPath, refuse := shellCommandString(raw)
	if !refuse {
		if hasTraceFlag(raw) {
			return "", false, &Refusal{Rule: "shell tracing (-x) echoes expanded variables", Advice: "drop -x"}
		}
		return content, true, nil
	}
	if scriptPath == "" {
		return "", false, nil
	}
	if wc, found := ev.written[scriptPath]; found {
		if hasTraceFlag(raw) {
			return "", false, &Refusal{Rule: "shell tracing (-x) echoes expanded variables", Advice: "drop -x"}
		}
		return wc, true, nil
	}
	return "", false, nil
}

// shell judges a shell command string by splitting it into simple commands
// and judging each, tracking variables assigned from Secrets.
func (ev *evaluator) shell(s string, depth int) error {
	if depth > maxDepth {
		return maxDepthRefusal
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
	// CLA-103: `cd` anywhere in this simple command invalidates every
	// pending write-then-run candidate (ev.written) — the safety valve
	// stream guidance calls "no intervening cd", kept blanket and
	// conservative (ANY cd, not only one whose own target this evaluator
	// can resolve to a literal) rather than reasoning precisely about
	// which entries a particular cd would or wouldn't invalidate. This
	// runs before the dynamic-command-name resolution just below so a
	// `cd` reached only through a resolved literal command name still
	// invalidates — though in practice `cd` itself is never spelled that
	// indirectly. skipCommandPrefix (hook.go) resolves past a
	// `command`/`builtin`/`exec` prefix first (CLA-103 review) so
	// `command cd ...`/`builtin cd ...` invalidate exactly like a bare
	// `cd` already does, rather than silently leaving a stale written
	// entry pointing at a directory this command never actually ran in.
	if cmd := skipCommandPrefix(rest, 0); cmd < len(rest) && base(rest[cmd].raw) == "cd" {
		ev.written = map[string]string{}
	}
	// CLA-103: record a heredoc-to-file write (`cat > p <<D`, `cat <<D >
	// p`, `cat >> p <<D`, `tee [-a] p <<D`) in THIS same shell string, so
	// a LATER script-by-path shell invocation of the identical literal
	// path — before this hook/run has actually created the file on disk
	// — can resolve to its body (ev.shellScriptContent) instead of
	// failing the on-disk read that hasn't happened yet.
	// heredocToFileWrite's own doc comment has the full, deliberately
	// narrow shape this recognizes and the reasons it declines anything
	// else.
	var recordedWrite string
	if path, body, appendMode, ok := heredocToFileWrite(rest); ok {
		resolved := ev.resolveLiteral(path)
		recordedWrite = resolved
		if appendMode {
			// A real `>>`/`tee -a` appends to whatever is already
			// there. An EARLIER write to this identical path already
			// tracked in ev.written (a `cat > FILE <<D` truncate,
			// or a prior append, seen earlier in this same shell
			// string) is checked FIRST and takes priority over a
			// real on-disk read: the whole point of ev.written is
			// that this hook/run's own check happens BEFORE either
			// write has actually executed, so the real file on disk
			// right now reflects neither — reading it instead of the
			// tracked state would silently drop an earlier write's
			// own content from what gets checked here (a `cat >
			// FILE <<D` of dangerous content, followed by `cat >>
			// FILE <<D` of a second, safe-looking body, must still
			// carry the first write's content forward, not launder
			// it away). Only when NO earlier write in this shell
			// string touched this path at all does this fall back to
			// a best-effort real on-disk read (the genuine "append to
			// a file that already existed before this command ran"
			// case); an unreadable/nonexistent path there is treated
			// as nothing to prepend, not a reason to fail this whole
			// command closed over an unrelated I/O problem — the
			// SUBSEQUENT script-by-path read, if this path is later
			// actually run, still applies every rule below to
			// whatever content this recorded.
			if existing, ok := ev.written[resolved]; ok {
				body = existing + body
			} else if diskExisting, err := os.ReadFile(resolved); err == nil {
				body = string(diskExisting) + body
			}
		}
		ev.written[resolved] = body
	}
	// CLA-103 review: a LATER write to a path already tracked in
	// ev.written, through any shape other than the one heredocToFileWrite
	// itself just recorded above (recordedWrite) — a plain `> PATH`/`>>
	// PATH` redirect on any program, a bare `tee PATH` with no heredoc, or
	// a cp/mv invocation — must invalidate that stale entry rather than
	// leave it certifying a LATER script-by-path run of that identical
	// path with content this evaluator never actually saw. See
	// invalidateOverwrittenWrites' own doc comment for the exact shapes
	// and why cp/mv/bare-tee blanket-clear rather than resolve precisely.
	invalidateOverwrittenWrites(rest, ev.written, recordedWrite, ev.resolveLiteral)
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
		// CLA-103: at the hook layer only (ev.traceAllowlist), `set -x`/
		// `set -o xtrace`/a combined short-flag group containing `x` is not
		// a reveal worth blocking everyday debugging over — see
		// Input.TraceAllowlist's own doc comment for why this is scoped to
		// the hook and no further (cpass run / the MCP server keep this
		// refusal unconditionally, since real execution DOES have real
		// Bound Secret values sitting in the process a traced script would
		// echo).
		if !ev.traceAllowlist {
			for _, a := range args {
				if (strings.HasPrefix(a.raw, "-") && !strings.HasPrefix(a.raw, "--") && strings.Contains(a.raw, "x")) || a.raw == "xtrace" {
					return &Refusal{Rule: "set -x echoes expanded variables", Advice: "drop -x"}
				}
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
		argsRaw := make([]string, len(args))
		for k, a := range args {
			argsRaw[k] = a.raw
		}
		patIdx := readerPatternIndex(prog, argsRaw)
		for k, a := range args {
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
			// command-policy:read-builtin-destination-name-not-a-
			// filename: read/mapfile/readarray's own positional words
			// are destination variable/array names, never a file
			// operand -- only a `< target` redirection word
			// (a.redirTarget) can be one for these three builtins,
			// unlike every other entry in `readers` (a real reader
			// program), whose ordinary positional words genuinely are
			// file arguments. Skip the filename-style checks below for
			// anything else, so e.g. `read -r id_rsa_output` is never
			// mistaken for reading the id_rsa* SSH key file -- the
			// reveal-style checks just above (a bound/tainted $VAR
			// reference, or one behind a same-shell-string fd alias)
			// still apply regardless, since those detect a genuinely
			// different shape that has nothing to do with a
			// destination name's own spelling.
			if readBuiltins[prog] && !a.redirTarget {
				continue
			}
			// command-policy:reader-pattern-argument-not-a-filename:
			// grep/sed/awk/jq/yq's own PATTERN/FILTER/SCRIPT argument
			// (see readerPatternIndex) is never a filename — the
			// reveal-style checks above still apply to it regardless
			// (a bound Secret used AS a pattern is still a reveal), only
			// the filename-style checks below are skipped.
			if k == patIdx {
				continue
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
		//
		// Each word is also resolved through ev.resolveLiteral first
		// (command-policy:shell-script-path-literal-variable): a script
		// path — or a -c string — stashed in a shell variable earlier
		// assigned a plain string literal in this same shell string
		// (`G=script.sh; bash $G`) is exactly what a real shell expands
		// before ever invoking bash, and is exactly as checkable as the
		// literal spelling `bash script.sh` already is; without this, `$G`
		// reaches shellCommandString as the literal two-byte text "$G",
		// which os.Stat obviously can't find, so a benign, ordinary
		// "script path held in a variable" invocation was refused as an
		// unresolvable shape even though the path it names is real and
		// readable.
		raw := make([]string, 0, len(args))
		for _, a := range args {
			if !a.hasHeredoc {
				raw = append(raw, ev.resolveLiteral(a.raw))
			}
		}
		content, ok, refusal := ev.shellScriptContent(raw)
		if refusal != nil {
			return refusal
		}
		if ok {
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
	// A shell name appearing among the ARGUMENTS here (rest[0] itself,
	// checked above, already ruled out) — `ssh host bash <<EOF ... EOF`,
	// `docker run --rm -i alpine sh <<EOF ... EOF` — is resolved from the
	// original word list, preserving any heredoc attached to it, before
	// any conversion to plain strings below: shellWordRefusalWords needs
	// the heredoc word's actual body (word.heredoc), which the
	// plain-string argv conversion just below would throw away (a
	// heredoc word's raw text is "" — see split.go's word doc comment),
	// wrongly making an ordinary "pipe a script into a wrapped shell's
	// stdin" invocation look statically unresolvable even though its
	// heredoc body sits right there
	// (command-policy:shell-behind-wrapper-heredoc-lost-on-argv-
	// conversion). ev.argv's own shellWordRefusal (below, via the
	// argv fallback) remains correct and unchanged for a literal argv
	// that never went through shell-string parsing at all (cpass run's
	// own direct Input.Argv, or an argv reached by unwrapping env/sudo/
	// timeout/etc.), which can never carry a heredoc to begin with.
	for _, w := range args {
		if shells[base(w.raw)] {
			return ev.shellWordRefusalWords(args, depth)
		}
	}
	// Anything else: judge as an argv, so nested shells, env, printenv apply.
	argv := make([]string, len(rest))
	for i, w := range rest {
		argv[i] = w.raw
	}
	return ev.argv(argv, depth+1)
}

// shellWordRefusalWords mirrors shellWordRefusal (below) — a shell name
// appearing anywhere in a word list, not only at position 0 — but works
// from the original []word rather than a flattened []string, so a heredoc
// attached to that later word is still visible as its executed script,
// and a script-path/-c argument that is a whole-word variable reference
// to an earlier plain-string literal is still resolved
// (command-policy:shell-behind-wrapper-heredoc-lost-on-argv-conversion,
// command-policy:shell-script-path-literal-variable). Called only from
// ev.simple's catch-all, which is the one place a []word list carrying a
// real heredoc/literal-tracking evaluator is available for this; a true
// literal argv (Input.Argv, never shell-parsed) can never carry a
// heredoc, so shellWordRefusal's plain-string version remains correct
// and unchanged for that path.
func (ev *evaluator) shellWordRefusalWords(words []word, depth int) error {
	for i := 0; i < len(words); i++ {
		prog := base(words[i].raw)
		if !shells[prog] {
			continue
		}
		rest := words[i+1:]
		raw := make([]string, 0, len(rest))
		for _, w := range rest {
			if !w.hasHeredoc {
				raw = append(raw, ev.resolveLiteral(w.raw))
			}
		}
		content, ok, refusal := ev.shellScriptContent(raw)
		if refusal != nil {
			return refusal
		}
		if ok {
			if err := ev.shell(content, depth+1); err != nil {
				return err
			}
			continue
		}
		if hd, ok := heredocArg(rest); ok {
			if err := ev.shell(hd.body, depth+1); err != nil {
				return err
			}
			continue
		}
		return &Refusal{
			Rule:   prog + "'s invocation shape can't be checked statically",
			Advice: `use -c "..." or a readable script file under 1 MiB (cpass reads and checks it) instead`,
		}
	}
	return nil
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
	return resolveLiteralIn(s, ev.literals)
}

// resolveLiteralIn is resolveLiteral's underlying logic, taking the
// literals map explicitly rather than through an *evaluator, so hookWalk
// — which has no *evaluator of its own (see its doc comment: it "does
// not touch the Bound/tainted evaluator" since it has no Bound vars to
// work from) — can resolve the same shape with its own, lighter
// leading-assignment tracking (command-policy:shell-script-path-literal-
// variable).
func resolveLiteralIn(s string, literals map[string]string) string {
	name, whole := wholeVarRef(s)
	if !whole {
		return s
	}
	if lit, ok := literals[name]; ok {
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
// any I/O). When this evaluator has no usable cwd — a genuinely
// well-formed glob this package simply has nothing to resolve it
// against — this fails closed (refuses) rather than silently letting an
// unresolvable glob pattern through unchecked, this package's existing
// default for any other shape it cannot statically resolve. A pattern
// that fails to PARSE as a glob at all (filepath.Glob's own
// ErrBadPattern — an unbalanced "[", the shape a reader's own
// PATTERN/FILTER/SCRIPT argument routinely takes, e.g. grep/sed's own
// regex or jq's `.[] | .name` filter) is different: it was never a
// filename-globbing attempt to begin with, so it is allowed, not
// refused — see the err != nil case below. A glob that resolves to
// nothing dangerous (parses fine, but no match at all, or matches that
// aren't Secret-bearing) is likewise allowed, exactly like an ordinary
// non-glob filename that isn't one.
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
		// A malformed glob pattern (filepath.ErrBadPattern — an unbalanced
		// "[", most commonly) is not a real shell glob at all: a real
		// shell's own filename globbing requires syntactically valid glob
		// syntax to begin with, so text that fails to parse as one was
		// never attempting to reference a file this way in the first
		// place, and cannot expand to one either. This is what a reader's
		// own PATTERN/FILTER/SCRIPT argument routinely looks like —
		// grep/sed/awk's regex, jq's `.[] | .name` filter — since regex
		// bracket expressions and substitution syntax are not valid glob
		// syntax; treated as "no glob match" (allow) rather than
		// "unresolvable" (refuse), unlike ev.cwd=="" just above, which IS
		// a genuinely well-formed glob this evaluator merely has nothing
		// to resolve it against (command-policy:glob-pattern-vs-reader-
		// filter-argument).
		return nil
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
