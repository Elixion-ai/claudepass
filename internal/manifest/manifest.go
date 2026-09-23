// Package manifest reads and writes the committed, per-project declaration
// of which Handles a project needs and their Bindings. A Manifest contains
// no Secret values and is safe to share.
package manifest

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Elixion-ai/claudepass/internal/atomicfile"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

// FileName is the Manifest file at a project root.
const FileName = ".claudepass.toml"

// ErrNotFound is returned when no Manifest exists in cwd or any ancestor.
var ErrNotFound = errors.New("no " + FileName + " found here or in any parent directory (run cpass manifest init)")

// Entry declares one Handle the project needs.
type Entry struct {
	Handle  string
	Binding vault.Binding // Name empty = Handle default; Kind empty = env
}

// Manifest is the parsed file.
type Manifest struct {
	Path    string
	Entries []Entry
	// GlobalDisabled records this project's `[options] global = false`:
	// the durable, committed opt-out from the Global Manifest. Only the
	// project Manifest ever carries it; on the Global Manifest itself it is
	// meaningless and never read.
	GlobalDisabled bool

	// extraOptions and extraSections keep, verbatim, every line of the file
	// this version of cpass does not itself parse — other keys inside
	// [options], and whole sections that are neither [options] nor
	// [secrets]. Load captures them and Save re-emits them unchanged, so a
	// `cpass manifest add` never silently drops a `[options] global = false`
	// written by a newer binary, or a section this one has not heard of.
	// Without this, Save — which regenerates the whole file from parsed
	// struct fields — would erase anything Load did not understand.
	extraOptions  []string
	extraSections []rawSection

	// global marks this as the machine-wide Manifest, so Save writes the
	// header that describes what the file actually is. LoadGlobal and
	// SaveGlobal set it; nothing else does.
	global bool
}

// rawSection is one unparsed section kept verbatim for round-tripping.
type rawSection struct {
	name  string
	lines []string
}

// Find walks up from dir looking for a Manifest.
func Find(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, FileName)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ErrNotFound
		}
		dir = parent
	}
}

// Load parses the Manifest at path.
//
// The format is a small TOML subset written by this package:
//
//	[secrets]
//	"stripe/live" = "STRIPE_SECRET_KEY"
//	"gcp/sa" = { binding = "GOOGLE_APPLICATION_CREDENTIALS", kind = "file" }
//	"github/token" = ""
func Load(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read handle: nothing buffered to lose on Close
	m := &Manifest{Path: path}
	sc := bufio.NewScanner(f)
	section := ""
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.TrimSpace(t[1 : len(t)-1])
			continue
		}
		if section == "options" {
			// The one recognised option. Anything else in this section —
			// another key, another value for this one — is kept verbatim
			// rather than guessed at.
			if k, v, ok := strings.Cut(t, "="); ok &&
				strings.TrimSpace(k) == "global" && strings.TrimSpace(v) == "false" {
				m.GlobalDisabled = true
				continue
			}
			m.extraOptions = append(m.extraOptions, t)
			continue
		}
		if section != "secrets" {
			m.captureExtra(section, t)
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, line)
		}
		handle := unquote(strings.TrimSpace(k))
		if err := vault.ValidateHandle(handle); err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, line, err)
		}
		e := Entry{Handle: handle, Binding: vault.Binding{Kind: vault.BindEnv}}
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "{") {
			for _, field := range strings.Split(strings.Trim(v, "{}"), ",") {
				fk, fv, ok := strings.Cut(field, "=")
				if !ok {
					continue
				}
				switch strings.TrimSpace(fk) {
				case "binding":
					e.Binding.Name = unquote(strings.TrimSpace(fv))
				case "kind":
					e.Binding.Kind = vault.BindingKind(unquote(strings.TrimSpace(fv)))
				}
			}
		} else {
			e.Binding.Name = unquote(v)
		}
		if e.Binding.Kind != vault.BindEnv && e.Binding.Kind != vault.BindFile {
			return nil, fmt.Errorf("%s:%d: kind must be env or file", path, line)
		}
		if e.Binding.Name == "" {
			e.Binding.Name = vault.DefaultBindingName(handle)
		}
		m.Entries = append(m.Entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

// Save writes the Manifest, atomically (internal/atomicfile: staged in a
// unique temp file next to m.Path, then renamed into place), so a reader —
// or a crash mid-write — never sees a partial file. Entries are sorted so
// diffs stay small.
func (m *Manifest) Save() error {
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Handle < m.Entries[j].Handle })
	var b strings.Builder
	if m.global {
		b.WriteString("# ClaudePass Global Manifest: the Handles every project on this machine gets.\n")
		b.WriteString("# No values live here. A project opts out with `cpass manifest global off`.\n\n")
	} else {
		b.WriteString("# ClaudePass manifest: the Handles this project needs. No values live here.\n")
		b.WriteString("# An Agent runs `cpass run -- <command>` and every Handle below is injected.\n\n")
	}
	if m.GlobalDisabled || len(m.extraOptions) > 0 {
		b.WriteString("[options]\n")
		if m.GlobalDisabled {
			b.WriteString("global = false\n")
		}
		for _, l := range m.extraOptions {
			b.WriteString(l + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("[secrets]\n")
	for _, e := range m.Entries {
		if e.Binding.Kind == vault.BindFile {
			fmt.Fprintf(&b, "%q = { binding = %q, kind = \"file\" }\n", e.Handle, e.Binding.Name)
		} else if e.Binding.Name == vault.DefaultBindingName(e.Handle) {
			fmt.Fprintf(&b, "%q = \"\"\n", e.Handle)
		} else {
			fmt.Fprintf(&b, "%q = %q\n", e.Handle, e.Binding.Name)
		}
	}
	for _, sec := range m.extraSections {
		fmt.Fprintf(&b, "\n[%s]\n", sec.name)
		for _, l := range sec.lines {
			b.WriteString(l + "\n")
		}
	}
	return atomicfile.Write(m.Path, []byte(b.String()), 0o644)
}

// captureExtra records one verbatim line of an unparsed section, keeping
// sections in the order they were first seen so Save reproduces the file's
// own shape rather than a sorted approximation of it.
func (m *Manifest) captureExtra(section, line string) {
	for i := range m.extraSections {
		if m.extraSections[i].name == section {
			m.extraSections[i].lines = append(m.extraSections[i].lines, line)
			return
		}
	}
	m.extraSections = append(m.extraSections, rawSection{name: section, lines: []string{line}})
}

// Add declares a Handle, replacing any existing declaration for it.
func (m *Manifest) Add(e Entry) {
	if e.Binding.Kind == "" {
		e.Binding.Kind = vault.BindEnv
	}
	if e.Binding.Name == "" {
		e.Binding.Name = vault.DefaultBindingName(e.Handle)
	}
	for i := range m.Entries {
		if m.Entries[i].Handle == e.Handle {
			m.Entries[i] = e
			return
		}
	}
	m.Entries = append(m.Entries, e)
}

// Remove undeclares a Handle, reporting whether it was there to remove.
func (m *Manifest) Remove(handle string) bool {
	for i := range m.Entries {
		if m.Entries[i].Handle == handle {
			m.Entries = append(m.Entries[:i], m.Entries[i+1:]...)
			return true
		}
	}
	return false
}

// Has reports whether the Handle is declared.
func (m *Manifest) Has(handle string) bool {
	for _, e := range m.Entries {
		if e.Handle == handle {
			return true
		}
	}
	return false
}

// unquote strips a value's surrounding quotes. Save always writes a
// double-quoted value through Go's %q, so a double-quoted string is
// unescaped with strconv.Unquote first — the exact inverse of %q — falling
// back to a plain strip when that fails (a hand-written value using an
// escape %q never produces, e.g. a bare backslash before a letter):
// Save/Load's own round trip stays exact without becoming stricter than
// Load already was about a hand-authored file. A single-quoted value (this
// package's own TOML subset never itself writes one, only Load accepts it)
// has no escapes at all and is always a plain strip.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	return s
}
