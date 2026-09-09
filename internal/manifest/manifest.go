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
	"strings"

	"claudepass/internal/vault"
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
	defer f.Close()
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
		if section != "secrets" {
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

// Save writes the Manifest. Entries are sorted so diffs stay small.
func (m *Manifest) Save() error {
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Handle < m.Entries[j].Handle })
	var b strings.Builder
	b.WriteString("# ClaudePass manifest: the Handles this project needs. No values live here.\n")
	b.WriteString("# An Agent runs `cpass run -- <command>` and every Handle below is injected.\n\n[secrets]\n")
	for _, e := range m.Entries {
		if e.Binding.Kind == vault.BindFile {
			fmt.Fprintf(&b, "%q = { binding = %q, kind = \"file\" }\n", e.Handle, e.Binding.Name)
		} else if e.Binding.Name == vault.DefaultBindingName(e.Handle) {
			fmt.Fprintf(&b, "%q = \"\"\n", e.Handle)
		} else {
			fmt.Fprintf(&b, "%q = %q\n", e.Handle, e.Binding.Name)
		}
	}
	return os.WriteFile(m.Path, []byte(b.String()), 0o644)
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

// Has reports whether the Handle is declared.
func (m *Manifest) Has(handle string) bool {
	for _, e := range m.Entries {
		if e.Handle == handle {
			return true
		}
	}
	return false
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}
