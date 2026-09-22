// Package cli implements the cpass command line.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strings"
)

// Version is injected at build time, via GoReleaser's ldflags
// (.goreleaser.yaml) — the archives `curl`/Homebrew install carry a real
// tag here. `go install .../cmd/cpass@<tag>` (README's third documented
// install method) never gets that injection, so this stays "dev" on that
// path; effectiveVersion is what actually decides what `cpass version`
// prints.
var Version = "dev"

// readBuildInfo is debug.ReadBuildInfo, indirected so a test can substitute
// a fake result without needing a real `go install` build of its own.
var readBuildInfo = debug.ReadBuildInfo

// effectiveVersion is what `cpass version`/`--version` prints. When Version
// wasn't injected by ldflags, it falls back to runtime/debug.ReadBuildInfo's
// Main.Version — the module version Go itself auto-embeds into every binary
// built with `go install pkg@version`, needing no ldflags at all — so that
// install path reports something better than "dev" too. "(devel)" is what
// ReadBuildInfo reports for a plain `go build` run against a local checkout
// with no resolved module version (e.g. this repo's own `go build
// ./cmd/cpass`): that case has nothing more useful to say than "dev"
// itself, so it's treated the same as no build info at all.
func effectiveVersion() string {
	if Version != "dev" {
		return Version
	}
	info, ok := readBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return Version
	}
	return info.Main.Version
}

// Exit codes.
const (
	ExitOK      = 0
	ExitError   = 1
	ExitUsage   = 2
	ExitRefused = 3
)

type env struct {
	args   []string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	// outMode and errMode are this env's colour mode for stdout and
	// stderr respectively, decided once (see ansi.go) when the env is
	// built: never re-detected mid-command, and never applied to a
	// stream other than the one it was decided for.
	outMode colorMode
	errMode colorMode
}

type command struct {
	name    string
	summary string
	run     func(e *env) int
}

var commands = map[string]command{}

func register(c command) { commands[c.name] = c }

// fprintf, fprintln and fprint write best-effort to a CLI output stream
// (the process's own stdout/stderr, or occasionally an Agent's). Their
// error is never actionable here: the command is already finishing,
// successfully or not, and there is nothing more useful to do with a
// broken stdout/stderr than what happens anyway — the process exits. The
// return values are intentionally discarded rather than propagated.
func fprintf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
func fprintln(w io.Writer, a ...any)               { _, _ = fmt.Fprintln(w, a...) }
func fprint(w io.Writer, a ...any)                 { _, _ = fmt.Fprint(w, a...) }

// Main runs cpass with the given arguments and returns the exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{
		args: args, stdin: stdin, stdout: stdout, stderr: stderr,
		outMode: streamColorMode(stdout), errMode: streamColorMode(stderr),
	}
	if len(args) == 0 || args[0] == "help" || isHelpFlag(args[0]) {
		usage(stdout)
		return ExitOK
	}
	if args[0] == "version" || args[0] == "--version" {
		fprintln(stdout, "cpass", effectiveVersion())
		return ExitOK
	}
	c, ok := commands[args[0]]
	if !ok {
		e.notice("unknown command %q", args[0])
		usage(stderr)
		return ExitUsage
	}
	e.args = args[1:]
	return c.run(e)
}

func usage(w io.Writer) {
	fprintln(w, "cpass — secrets for AI coding agents. Agents see Handles, never values.")
	fprintln(w)
	fprintln(w, "Usage: cpass <command> [flags]")
	fprintln(w)
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fprintf(w, "  %-10s %s\n", n, commands[n].summary)
	}
	fprintf(w, "  %-10s %s\n", "version", "print the version")
}

// isHelpFlag reports whether s is either spelling of a bare help flag.
// Main's own top-level dispatch uses it, and so does every dispatcher-style
// subcommand (manifest, keychain, integrate) that switches on e.args[0] as
// a subcommand name rather than parsing it with a flag.FlagSet: without
// this check, -h/--help there falls into the same "unknown subcommand"
// branch as a typo, exiting ExitUsage instead of printing a usage synopsis
// and exiting 0 like every flag.FlagSet-based subcommand's own -h/--help
// already does via usageErr.
func isHelpFlag(s string) bool { return s == "-h" || s == "--help" }

// parseInterspersed parses flags that may appear before or after positional
// arguments (Go's flag package stops at the first positional).
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// fail prints a one-line error and returns the exit code.
func (e *env) fail(code int, format string, a ...any) int {
	msg := fmt.Sprintf(format, a...)
	fprintln(e.stderr, "cpass: "+strings.TrimSuffix(msg, "\n"))
	return code
}

func (e *env) failErr(err error) int {
	var code = ExitError
	if errors.Is(err, errLocked) {
		code = ExitError
	}
	return e.fail(code, "%v", err)
}

var errLocked = errors.New("locked")

// usageErr turns a flag.FlagSet parse failure — an unknown or malformed
// flag, or a bare -h/--help — into the same "cpass: ..." diagnostic every
// other error uses, so a subcommand's own flag handling can never fall
// through to the flag package's raw, unprefixed, mixed-case, multi-line
// output (docs/CLI-STYLE.md Voice: every diagnostic is "cpass: <message>",
// one line). Every FlagSet passed through this path is built with
// fs.SetOutput(io.Discard) for exactly this reason — flag never gets to
// write anything itself, on a parse error or on -h/--help alike — and each
// call site passes the same one-line "cpass <command> ..." synopsis it
// already shows for a bad positional-argument count, so there is exactly
// one string to keep in sync per command. -h/--help (flag.ErrHelp) prints
// that synopsis to stdout and exits 0, mirroring Main's own top-level
// `cpass help`/`-h` handling; any other parse error keeps flag's own
// message — already lowercase and terse — appends the usage synopsis, and
// gets the "cpass: " prefix via fail, exiting ExitUsage like any other
// usage error.
func (e *env) usageErr(err error, usage string) int {
	if errors.Is(err, flag.ErrHelp) {
		fprintln(e.stdout, "usage: "+usage)
		return ExitOK
	}
	return e.fail(ExitUsage, "%v; usage: %s", err, usage)
}

// paintErr and paintOut colour s for role using this env's stderr/stdout
// colour mode respectively — the single point every helper below routes
// through, so ansi.go's detection is the only place that decides whether
// any escape byte is ever written.
func (e *env) paintErr(role brandRole, s string) string { return e.errMode.paint(role, s) }
func (e *env) paintOut(role brandRole, s string) string { return e.outMode.paint(role, s) }

// notice writes a plain "cpass: <message>" diagnostic to stderr — the
// fallback for any hand-written diagnostic that doesn't match one of the
// specific grammars below (docs/CLI-STYLE.md "Message grammar"). It never
// applies colour: a plain notice carries no brand role of its own.
func (e *env) notice(format string, a ...any) {
	fprintln(e.stderr, "cpass: "+fmt.Sprintf(format, a...))
}

// refusalTextForMode renders docs/CLI-STYLE.md's refusal grammar — "cpass:
// refused: <what> — <do instead>" — colouring the whole line red (the role
// docs/CLI-STYLE.md's Colour section assigns to refusals) under an
// explicitly given colour mode, rather than a stream's TTY-derived one.
// `cpass policy --hook` and `cpass intercept` (see interceptcmd.go's use of
// storedTextForMode) are consumed by Claude Code's hook machinery, never
// shown on a raw fd a human is necessarily watching as a terminal, and the
// hook protocol re-displays this exact text to the human itself — so those
// call sites must always pass colorNone here regardless of what the hook
// subprocess's own stderr happens to be (a pty, a supervisor-attached
// terminal, ...), independent of the env's errMode.
func refusalTextForMode(mode colorMode, what, insteadDo string) string {
	return mode.paint(roleRed, "cpass: refused: "+what+" — "+insteadDo)
}

// refusalText is refusalTextForMode using this env's stream-derived
// errMode — the common case for every refusal a human's own terminal may
// show directly. refuse uses it for the common case; `cpass policy --hook`
// calls refusalTextForMode(colorNone, ...) directly instead (see above).
func (e *env) refusalText(what, insteadDo string) string {
	return refusalTextForMode(e.errMode, what, insteadDo)
}

// refuse writes a Command Policy refusal in the one grammar every refusal
// must use and returns ExitRefused, so a call site never has to spell the
// shape (or the exit code) out itself.
func (e *env) refuse(what, insteadDo string) int {
	fprintln(e.stderr, e.refusalText(what, insteadDo))
	return ExitRefused
}

// storedTextForMode renders one "<kind> as <handle>" fragment of
// docs/CLI-STYLE.md's "cpass: stored <kind> as <handle>; …" row: the Handle
// ember (the role the Colour section assigns to a Handle everywhere it
// appears) and kind dim grey (secondary detail next to it), under an
// explicitly given colour mode rather than a stream's TTY-derived one.
// cmdIntercept (interceptcmd.go) — Claude Code's UserPromptSubmit hook,
// which re-displays this text to the human itself — always passes
// colorNone here, the same reasoning as refusalTextForMode above.
func storedTextForMode(mode colorMode, kind, handle string) string {
	return mode.paint(roleDim, kind) + " as " + mode.paint(roleEmber, handle)
}

// stored is storedTextForMode using this env's stream-derived errMode.
// Callers with more than one fragment join them with a plain comma
// (docs/CLI-STYLE.md's Intercept row: "<kind> as <handle>[, <kind> as
// <handle>…]") before wrapping the result in a notice.
func (e *env) stored(kind, handle string) string {
	return storedTextForMode(e.errMode, kind, handle)
}

// exposed renders docs/CLI-STYLE.md's Exposed-reminder line: "cpass:
// <handle> is Exposed since <date>, rotate it" — the Handle ember, the
// Exposed state red, and the date dim grey (secondary detail), matching
// the Colour section's role for each.
func (e *env) exposed(handle, since string) string {
	return "cpass: " + e.paintErr(roleEmber, handle) + " is " + e.paintErr(roleRed, "Exposed") +
		" since " + e.paintErr(roleDim, since) + ", rotate it"
}

// locked renders docs/CLI-STYLE.md's locked-Vault line, colouring the
// suggested command cyan — the role the Colour section assigns to hints.
func (e *env) locked() string {
	return "cpass: vault is locked, run " + e.paintErr(roleCyan, "cpass unlock")
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	return isTTY(f)
}
