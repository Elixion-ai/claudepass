package cli

import (
	"fmt"
	"io"
	"os"
)

// This file is the implementation of docs/CLI-STYLE.md's "Colour (ANSI, TTY
// only)" section. The two must not diverge: a change to a rule or an
// escape code here needs the matching sentence in that section updated in
// the same commit, and vice versa.
//
// Detection order, matching the style guide exactly:
//  1. NO_COLOR set to any non-empty value -> no colour, unconditionally.
//  2. The destination is not a TTY -> no colour (piped or captured output
//     stays plain, which is what every e2e assertion on cpass's stdout or
//     stderr relies on).
//  3. TERM=dumb -> no colour.
//  4. COLORTERM is "truecolor" or "24bit" -> 24-bit escapes.
//  5. Otherwise -> the 256-colour fallback escapes below.
//
// Palette (docs/CLI-STYLE.md "Colour"):
//   - ember  256=208 truecolor #ff8a1f — the Handle, success.
//   - cyan   256=45  truecolor #4de8ff — hints, the `cpass run` shield.
//   - red    256=203 truecolor #ff4d4d — refusals, the [REDACTED] marker, Exposed.
//   - dim grey 256=245 truecolor #b3a89b (the brand's text-muted) — secondary detail.
//
// Reset is always ESC[0m.

// colorMode is how (or whether) a destination stream may be coloured.
type colorMode int

const (
	colorNone colorMode = iota
	color256
	colorTrue
)

// ansiReset ends any colour segment this file opens.
const ansiReset = "\x1b[0m"

// brandRole is one of the four palette roles docs/CLI-STYLE.md assigns
// meaning to. Never introduce a fifth without updating that section too.
type brandRole struct {
	idx256  int
	r, g, b uint8
}

var (
	roleEmber = brandRole{idx256: 208, r: 0xff, g: 0x8a, b: 0x1f}
	roleCyan  = brandRole{idx256: 45, r: 0x4d, g: 0xe8, b: 0xff}
	roleRed   = brandRole{idx256: 203, r: 0xff, g: 0x4d, b: 0x4d}
	roleDim   = brandRole{idx256: 245, r: 0xb3, g: 0xa8, b: 0x9b}
)

// detectColorMode decides the colour mode for one destination stream. It
// takes isTTY and getenv as parameters, never asking the OS itself, so
// tests can drive every branch (a TTY stub, a fake NO_COLOR/COLORTERM/TERM)
// without ever spawning a real pty.
func detectColorMode(isTTY bool, getenv func(string) string) colorMode {
	if getenv("NO_COLOR") != "" {
		return colorNone
	}
	if !isTTY {
		return colorNone
	}
	if getenv("TERM") == "dumb" {
		return colorNone
	}
	switch getenv("COLORTERM") {
	case "truecolor", "24bit":
		return colorTrue
	default:
		return color256
	}
}

// isTerminalWriter reports whether w is the process's own terminal, the
// write-side counterpart of isTerminal (tty.go) for an io.Reader.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && isTTY(f)
}

// streamColorMode is detectColorMode wired to the real OS environment and a
// real destination stream, called once per stream when an env is built.
func streamColorMode(w io.Writer) colorMode {
	return detectColorMode(isTerminalWriter(w), os.Getenv)
}

// escape returns the ANSI SGR sequence that starts role m, or "" when m is
// colorNone.
func (m colorMode) escape(role brandRole) string {
	switch m {
	case colorTrue:
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", role.r, role.g, role.b)
	case color256:
		return fmt.Sprintf("\x1b[38;5;%dm", role.idx256)
	default:
		return ""
	}
}

// paint wraps s in role's colour for this mode. With colorNone it returns s
// unchanged — byte-for-byte identical to a build with no colour support at
// all, which is what every non-TTY (piped, captured, e2e) destination gets.
func (m colorMode) paint(role brandRole, s string) string {
	if m == colorNone {
		return s
	}
	return m.escape(role) + s + ansiReset
}

// markerDecorator returns a redact.WithMarkerDecorator func that colours a
// child's [REDACTED:...] marker red (docs/CLI-STYLE.md: red covers "the
// [REDACTED] marker") for mode, or nil when mode is colorNone. redact.Writer
// treats a nil decorator exactly like no option at all, so a non-TTY (or
// NO_COLOR, or TERM=dumb) destination's marker bytes are Marker(handle),
// unchanged — this is the "replacement-string decoration at the boundary
// where the replacement is chosen" deliverable, kept out of the matcher
// entirely: it only ever sees a marker scan has already decided to write.
func markerDecorator(mode colorMode) func(handle string, marker []byte) []byte {
	if mode == colorNone {
		return nil
	}
	return func(_ string, marker []byte) []byte {
		return []byte(mode.paint(roleRed, string(marker)))
	}
}
