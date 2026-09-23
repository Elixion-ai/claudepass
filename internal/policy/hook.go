package policy

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Elixion-ai/claudepass/internal/broker"
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
//   - references a live file-Binding's run-directory path by literal path
//     (ProtectedDirs, the same rule `cpass run` itself applies — see
//     runProtectedDirs);
//   - carries a raw Secret-shaped literal (the CLA-10 detector) — again
//     the same rule Evaluate applies, checked here unconditionally for the
//     same reason;
//   - gives `cpass add` an inline value instead of letting it prompt — the
//     one rule with no equivalent in Evaluate, since only the hook
//     inspects a raw command line before cpass has parsed anything; or
//   - trips one of the ordinary Bound-independent Command Policy rules
//     that need the command's real argv[0] to fire (env/printenv/set/
//     export dumps) and is itself a `cpass run` invocation with the
//     rule-tripping program buried inside its wrapped command (`cpass run
//     -- env`, where "env" is never argv[0] of anything this hook's own
//     per-word scan or Evaluate's shell-string parse treats as a command
//     position) — cpass run's own execution-time re-check (with the real,
//     unwrapped argv) still catches these; every other rule below,
//     including a file read at any depth, is checked here regardless of
//     whether command wraps `cpass run`, not only once cpass run itself
//     starts.
func EvaluateHook(command string) error {
	if strings.TrimSpace(command) == "" {
		return nil
	}
	if r := hookWalk(command, 0, map[string]string{}, map[string]string{}); r != nil {
		return r
	}
	// Same raw-literal rule Evaluate applies (see the package doc
	// comment), checked here unconditionally — since no Bound var is
	// needed to judge a literal.
	if len(detect.ScanStrict(command)) > 0 {
		return &Refusal{
			Rule:   "the command carries a raw Secret-shaped value",
			Advice: "store it first (`cpass capture`, or paste it so it's Intercepted) and reference it by Handle",
		}
	}
	// The full Evaluate — including the fd-alias and glob-expansion
	// mechanisms hookWalk's own lighter per-word scan does not implement
	// — runs unconditionally, including when command wraps a `cpass run`
	// invocation: hookWalk alone previously missed those two mechanisms
	// for a wrapped invocation specifically (`cpass run -- bash -c 'exec
	// 3< .env; cat <&3'`), a real gap between what this hook is documented
	// to catch and what it actually did, closed by always running this
	// check rather than deferring it to cpass run's own execution-time
	// Evaluate call (internal/run.Run makes that call too, so this is
	// deliberately redundant for a wrapped invocation, not newly
	// expensive in any way that matters: it is the same catch, just made
	// to also happen before the cpass run subprocess starts, matching
	// this function's own doc comment above).
	//
	// EnvAllowlist: true opts the well-known non-secret variable names in
	// hookEnvAllowlist below out of the printenv reveal refusal — see
	// Input.EnvAllowlist's own doc comment (CLA-102) for why this is set
	// here and nowhere else Evaluate is called from. TraceAllowlist: true
	// is the same shape for `set -x`/shell tracing (CLA-103) — see
	// Input.TraceAllowlist's own doc comment.
	in := Input{Argv: []string{"sh", "-c", command}, ProtectedDirs: runProtectedDirs(), EnvAllowlist: true, TraceAllowlist: true}
	if err := Evaluate(in); err != nil {
		return err
	}
	return nil
}

// hookEnvAllowlist is the small, fixed set of well-known, non-secret
// variable names `printenv NAME` may name at the PreToolUse hook layer
// without being refused (CLA-102): ordinary shell/session/toolchain
// variables no cpass user has ever Bound a Secret to, whose value an
// Agent routinely needs for everyday debugging (what's on PATH, which Go
// toolchain, which virtualenv is active, ...). LC_* and XDG_* are
// recognised by prefix (hookEnvAllowed below) rather than listed
// individually, matching how a real shell environment actually
// populates them (LC_ALL, LC_CTYPE, LC_COLLATE, ...; XDG_CONFIG_HOME,
// XDG_CACHE_HOME, XDG_DATA_HOME, ...). Documented in docs/SECURITY.md —
// the two must never diverge.
var hookEnvAllowlist = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "SHELL": true,
	"PWD": true, "OLDPWD": true, "LANG": true, "TERM": true,
	"TMPDIR": true, "GOPATH": true, "GOROOT": true, "GOBIN": true,
	"NODE_ENV": true, "VIRTUAL_ENV": true, "CONDA_PREFIX": true,
	"JAVA_HOME": true, "EDITOR": true, "PAGER": true, "HOSTNAME": true,
}

// hookEnvAllowed reports whether name is on hookEnvAllowlist above, or
// matches one of its two recognised prefixes (LC_*/XDG_*).
func hookEnvAllowed(name string) bool {
	if hookEnvAllowlist[name] {
		return true
	}
	return strings.HasPrefix(name, "LC_") || strings.HasPrefix(name, "XDG_")
}

// printenvAllowlisted reports whether args — the words following
// `printenv` — are one or more bare NAME arguments, every one of them
// hookEnvAllowed: `printenv` with NO arguments dumps every variable
// (still refused, matching bare env/printenv elsewhere in this package),
// and a single non-allow-listed name anywhere in the list — mixed in
// with allow-listed ones or not — keeps the whole invocation refused
// rather than silently printing just that one (`printenv PATH
// AWS_SECRET_ACCESS_KEY` stays refused).
func printenvAllowlisted(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		if !hookEnvAllowed(a) {
			return false
		}
	}
	return true
}

// runProtectedDirs returns the file-Binding run-directory root ProtectedDirs
// guards ($CPASS_HOME/run), the same root internal/run.Run itself passes to
// Evaluate — so a raw Bash call the Agent makes directly (not through
// cpass run) can't cat a live file-Binding's plaintext Secret by literal
// path either. This replicates internal/run's own runRoot logic locally
// rather than importing internal/run, which itself imports internal/policy
// (CLA-38); importing internal/broker here instead avoids that cycle. A
// broker.Home error (unreadable config dir) yields no protected dirs rather
// than failing the whole hook closed on an unrelated I/O problem — the
// secret-file-glob and raw-literal rules above still apply regardless.
func runProtectedDirs() []string {
	home, err := broker.Home()
	if err != nil {
		return nil
	}
	return []string{filepath.Join(home, "run")}
}

// hookWalk recurses through command the same way splitCommands' consumers
// elsewhere in this package do — into command substitutions and nested
// `shell -c STRING`/script-path/heredoc-body invocations — checking
// every simple command for a Secret-file read or a `cpass add` given an
// inline value. It does not touch the Bound/tainted evaluator (no Bound
// vars exist yet at this point), but it does track plain-string variable
// literals (`G=script.sh`) the same narrow way ev.simple's own
// ev.literals does, via the literals map threaded through every
// recursive call in one EvaluateHook pass — needed to resolve a shell
// invocation's own script-path/-c argument back to a real, checkable
// path when it's a whole-word reference to one
// (command-policy:shell-script-path-literal-variable): `G=deploy.sh;
// bash $G` should read exactly like `bash deploy.sh` already does, not
// refuse "$G" as an unresolvable, nonexistent path. written mirrors
// evaluator.written (policy.go) for CLA-103's write-then-run tracking —
// a `cat > PATH <<DELIM ... DELIM` seen earlier in this same
// EvaluateHook pass, so a LATER `bash PATH` in the same command can
// resolve to that body instead of failing the on-disk read that hasn't
// happened yet (see hookResolveScript below).
func hookWalk(command string, depth int, literals, written map[string]string) *Refusal {
	if depth > maxDepth {
		return maxDepthRefusal
	}
	for _, words := range splitCommands(command) {
		if len(words) == 0 {
			continue
		}
		// Leading VAR=value assignments (a plain string literal, no `$`
		// of its own): recorded the same way ev.simple's identical loop
		// records ev.literals, so a later bare $VAR/${VAR} in THIS
		// simple command's own shell-invocation words can be resolved
		// back to it, below.
		j := 0
		for j < len(words) {
			m := assignment.FindStringSubmatch(words[j].raw)
			if m == nil {
				break
			}
			if !strings.ContainsRune(m[2], '$') {
				literals[m[1]] = m[2]
			}
			j++
		}
		// CLA-103: `cd` anywhere in this simple command invalidates every
		// pending write-then-run candidate — see evaluator.written's own
		// doc comment (policy.go) for why this is blanket/conservative
		// rather than precise about which entries a particular cd would
		// or wouldn't invalidate. skipCommandPrefix resolves past a
		// `command`/`builtin`/`exec` prefix first (CLA-103 review) so
		// `command cd ...`/`builtin cd ...` invalidate exactly like a
		// bare `cd` already does, rather than silently leaving a stale
		// written entry pointing at a directory this command never
		// actually ran in.
		if cmd := skipCommandPrefix(words, j); cmd < len(words) && base(words[cmd].raw) == "cd" {
			for k := range written {
				delete(written, k)
			}
		}
		// CLA-103: record a heredoc-to-file write (`cat > p <<D`, `cat
		// <<D > p`, `cat >> p <<D`, `tee [-a] p <<D`) in THIS same
		// command, so a LATER script-by-path shell invocation of the
		// identical literal path can resolve to its body instead of
		// failing the on-disk read that hasn't happened yet
		// (hookResolveScript below; heredocToFileWrite's own doc comment,
		// policy.go, has the full shape).
		var recordedWrite string
		if path, body, appendMode, ok := heredocToFileWrite(words[j:]); ok {
			resolved := resolveLiteralIn(path, literals)
			recordedWrite = resolved
			if appendMode {
				// An earlier write to this identical path tracked in
				// written already (from earlier in this same command)
				// takes priority over a real on-disk read — see
				// evaluator's identical case (policy.go) for why:
				// this whole check runs before either write has
				// actually executed, so the real file on disk right
				// now reflects neither, and reading it instead of the
				// tracked state would silently drop an earlier
				// write's own content from what gets checked here.
				if existing, ok := written[resolved]; ok {
					body = existing + body
				} else if diskExisting, err := os.ReadFile(resolved); err == nil {
					body = string(diskExisting) + body
				}
			}
			written[resolved] = body
		}
		// CLA-103 review: a LATER write to a path already tracked in
		// written, through any shape other than the one heredocToFileWrite
		// itself just recorded above (recordedWrite) — a plain `>
		// PATH`/`>> PATH` redirect on any program, a bare `tee PATH` with
		// no heredoc, or a cp/mv invocation — must invalidate that stale
		// entry, mirroring evaluator.simple's identical call (policy.go).
		// See invalidateOverwrittenWrites' own doc comment for the exact
		// shapes and why cp/mv/bare-tee blanket-clear rather than resolve
		// precisely.
		invalidateOverwrittenWrites(words[j:], written, recordedWrite, func(s string) string {
			return resolveLiteralIn(s, literals)
		})
		for _, w := range words {
			for _, sub := range w.subs {
				if r := hookWalk(sub, depth+1, literals, written); r != nil {
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
			// The `.`/`source` builtins only mean "execute this file's
			// content" at an actual command position — elsewhere `.` is
			// just an ordinary argument (find .'s current-directory
			// argument, ls .'s target, ...), never a Secret-file read.
			if sourceBuiltins[prog] && commandStart(words, i) {
				for _, arg := range words[i+1:] {
					if matchesSecretFile(arg.raw) {
						return &Refusal{
							Rule:   w.raw + " would read " + arg.raw + ", a Secret-bearing file",
							Advice: "use `cpass run` (or the Manifest) instead of reading the file directly",
						}
					}
				}
			}
			if readers[prog] && !isCoincidentalReaderSubcommand(rawWordAt(words), commandStartIndex(words), i) {
				// isCoincidentalReaderSubcommand (policy.go, CLA-101
				// review) is what keeps a reader behind a wrapper this
				// list doesn't enumerate (`find . -exec cat .env \;`,
				// `timeout 5 cat .env`, `nice cat .env`, `xargs cat <
				// .env`, `sudo cat .env`, `docker exec c cat .env`,
				// `chroot / cat .env`, `strace -f cat .env`, `setsid cat
				// .env`, `unshare cat .env`, `stdbuf -oL cat .env`, ...)
				// refused at ANY word position, while excluding only the
				// small, specific set of multi-level CLI subcommands that
				// merely share a reader's name without behaving like one
				// (`aws logs tail ...`, `kubectl cp ...`) — see its own
				// doc comment.
				//
				// A pure-output program's own arguments are data it
				// prints, not programs it runs: `echo cat .env` never
				// executes cat. This exempts only an argument of
				// echo/printf/print's own command line — word 0 of this
				// simple command, or the first word after a leading run of
				// VAR=value assignments, so a printer prefixed with one (e.g.
				// DEBUG=1 echo ...) is exempted the same way (printerArg,
				// CLA-64 review).
				if !printerArg(words, i) {
					rest := words[i+1:]
					restRaw := make([]string, len(rest))
					for k, ww := range rest {
						restRaw[k] = ww.raw
					}
					patIdx := readerPatternIndex(prog, restRaw)
					for k, arg := range rest {
						// command-policy:read-builtin-destination-name-not-
						// a-filename: read/mapfile/readarray's own
						// positional words are destination variable/array
						// names, never a file path — only a `< target`
						// redirection word (arg.redirTarget) can be one
						// for these three builtins (see policy.go's
						// readBuiltins and ev.simple's identical guard),
						// unlike every other `readers` entry, whose
						// ordinary positional words genuinely are file
						// arguments.
						if readBuiltins[prog] && !arg.redirTarget {
							continue
						}
						// command-policy:reader-pattern-argument-not-a-
						// filename: grep/sed/awk/jq/yq's own PATTERN/
						// FILTER/SCRIPT argument (see readerPatternIndex)
						// is never a filename.
						if k == patIdx {
							continue
						}
						if matchesSecretFile(arg.raw) {
							return &Refusal{
								Rule:   w.raw + " would read " + arg.raw + ", a Secret-bearing file",
								Advice: "use `cpass run` (or the Manifest) instead of reading the file directly",
							}
						}
					}
				}
			}
			if shells[prog] {
				// Resolve what this shell invocation actually executes
				// the same way regardless of an attached heredoc — a
				// `-c STRING` or script-by-path argument, when present,
				// is what a real shell runs; an attached heredoc is just
				// stdin data for that invocation (see policy.go's
				// identical shells[prog] case). shellCommandString is
				// tried first, over raw with the heredoc placeholder
				// word filtered out so it can never be mistaken for -c's
				// value or a script path; only when neither resolves
				// does the heredoc's body become the executed script.
				// Previously the heredoc was checked first and, when
				// present, evaluated instead of a real -c/script-path
				// argument alongside it — a full, silent bypass (CLA-62
				// review).
				rest := words[i+1:]
				raw := make([]string, 0, len(rest))
				for _, ww := range rest {
					if !ww.hasHeredoc {
						// command-policy:shell-script-path-literal-variable:
						// resolve a whole-word $VAR/${VAR} script-path or -c
						// argument back to an earlier plain-string literal
						// assignment in this same command, the same way
						// policy.go's identical shells[prog] case does via
						// ev.resolveLiteral — `G=deploy.sh; bash $G` reads
						// like `bash deploy.sh`, not an unresolvable "$G".
						raw = append(raw, resolveLiteralIn(ww.raw, literals))
					}
				}
				content, ok := hookResolveScript(raw, written)
				if ok {
					if r := hookWalk(content, depth+1, literals, written); r != nil {
						return r
					}
					continue
				}
				if hd, ok := heredocArg(rest); ok {
					if r := hookWalk(hd.body, depth+1, literals, written); r != nil {
						return r
					}
					continue
				}
				return &Refusal{
					Rule:   w.raw + "'s invocation shape can't be checked statically",
					Advice: `use -c "..." or a readable script file under 1 MiB (cpass reads and checks it) instead`,
				}
			}
		}
	}
	return nil
}

// hookResolveScript mirrors evaluator.shellScriptContent (policy.go) for
// hookWalk's own, evaluator-less recursion: shellCommandString's own -c
// STRING / on-disk script-by-path result when that succeeds, or — when a
// script-by-path argument was named but isn't yet readable from disk —
// the body CLA-103's write-then-run tracking (written) recorded for that
// identical literal path earlier in this same shell string. ok is false
// for every other unresolvable shape, exactly like shellScriptContent.
// Unlike shellScriptContent, this never itself refuses on a trace flag
// (`bash -x script.sh`): hookWalk has no such rule of its own — see its
// own doc comment — the full Evaluate call EvaluateHook always also
// makes re-parses the same command text and applies that rule there.
func hookResolveScript(raw []string, written map[string]string) (content string, ok bool) {
	content, scriptPath, refuse := shellCommandString(raw)
	if !refuse {
		return content, true
	}
	if scriptPath == "" {
		return "", false
	}
	wc, found := written[scriptPath]
	return wc, found
}

// commandStart reports whether word position i in words is where a shell
// command name is expected: position 0, right after a leading run of
// VAR=value assignments, or right after command/builtin/exec. Only there
// does a bare "." mean the source builtin.
func commandStart(words []word, i int) bool {
	if i == 0 {
		return true
	}
	prev := base(words[i-1].raw)
	if prev == "command" || prev == "builtin" || prev == "exec" {
		return true
	}
	if !assignment.MatchString(words[i-1].raw) {
		return false
	}
	for j := 0; j < i; j++ {
		if !assignment.MatchString(words[j].raw) {
			return false
		}
	}
	return true
}

// skipCommandPrefix returns the index, starting the search at i, of the
// word in words that names the command actually being run — skipping
// over any leading run of `command`/`builtin`/`exec` prefix words, the
// same prefix commandStart (above) already recognizes a single one of at
// a specific position. CLA-103 review: the write-then-run `cd`-
// invalidation checks in both hookWalk (this file) and evaluator.simple
// (policy.go) compared the word at this position to "cd" directly,
// missing `command cd ...`/`builtin cd ...` — both ordinary, working
// shell syntax — so a real `cd` reached through either prefix silently
// left a stale ev.written/written entry pointing at a directory the
// command never actually ran in, letting a later same-named write-then-
// run resolve to the wrong file's tracked body. Chained prefixes
// (`command builtin cd`) are followed all the way through, matching real
// shell semantics: `command` and `builtin` each unambiguously name their
// own next word as the command to run, however many are stacked. The
// returned index may equal len(words); every caller already checks that
// bound itself before indexing, the same contract commandStartIndex
// (below) and ev.simple's own leading-assignment index already have.
func skipCommandPrefix(words []word, i int) int {
	for i < len(words) {
		p := base(words[i].raw)
		if p != "command" && p != "builtin" && p != "exec" {
			break
		}
		i++
	}
	return i
}

// commandStartIndex returns the index of a command's own program-name
// word within words: position 0, or the first word after a leading run
// of VAR=value assignments — the same position commandStart (above) and
// printerArg (below) each locate for their own purposes, but as an
// index rather than a boolean, since isCoincidentalReaderSubcommand
// (policy.go) needs to know which word is a multi-level CLI's own
// program name to look it up in coincidentalReaderSubcommands.
func commandStartIndex(words []word) int {
	j := 0
	for j < len(words) && assignment.MatchString(words[j].raw) {
		j++
	}
	return j
}

// rawWordAt adapts a []word list to the wordAt(int) string shape
// isCoincidentalReaderSubcommand (policy.go) takes, so hookWalk's
// per-word reader scan can share that exact same coincidental-
// subcommand denylist logic with readerWordRefusal's flat-argv
// equivalent — out-of-range indices (a path that would reach past
// either end of words) return "", which never equals a real subcommand
// segment, matching wordAt's existing contract.
func rawWordAt(words []word) func(int) string {
	return func(k int) string {
		if k < 0 || k >= len(words) {
			return ""
		}
		return words[k].raw
	}
}

// printerArg reports whether word position i in words is an argument
// printed by this simple command's own echo/printf/print: its command word
// (word 0, or the first word after a leading run of VAR=value assignments,
// found the same way commandStart finds one) must itself be a printer, and
// i must come strictly after it. This is what exempts `echo cat .env` and
// `DEBUG=1 echo cat .env` alike (CLA-64, and CLA-64's review fix for the
// leading-assignment case) — a reader word here is data the printer
// prints, not a program that runs.
func printerArg(words []word, i int) bool {
	j := 0
	for j < len(words) && assignment.MatchString(words[j].raw) {
		j++
	}
	return j < len(words) && i > j && printers[base(words[j].raw)]
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
