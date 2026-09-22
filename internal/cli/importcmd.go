package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Elixion-ai/claudepass/internal/dotenv"
	"github.com/Elixion-ai/claudepass/internal/manifest"
	"github.com/Elixion-ai/claudepass/internal/vault"
)

func init() {
	register(command{"import", "move a dotenv file's entries into the Vault: cpass import <path> [--prefix P] [--keep]", cmdImport})
}

func cmdImport(e *env) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	prefix := fs.String("prefix", "", "Handle prefix for every imported entry (e.g. myapp/)")
	keep := fs.Bool("keep", false, "leave the source file in place instead of shredding it")
	pos, err := parseInterspersed(fs, e.args)
	if err != nil {
		return e.usageErr(err, "cpass import <path> [--prefix P] [--keep]")
	}
	if len(pos) != 1 {
		return e.fail(ExitUsage, "usage: cpass import <path> [--prefix P] [--keep]")
	}
	path := pos[0]

	raw, err := os.ReadFile(path)
	if err != nil {
		return e.failErr(err)
	}
	parsed, err := dotenv.Parse(string(raw))
	if err != nil {
		return e.failErr(err)
	}
	if len(parsed) == 0 {
		return e.fail(ExitError, "%s has no entries to import", path)
	}

	type item struct {
		handle, binding, value string
	}
	pfx := normalizePrefix(*prefix)
	seen := map[string]bool{}
	items := make([]item, 0, len(parsed))
	for _, en := range parsed {
		handle := pfx + strings.ToLower(en.Name)
		if err := vault.ValidateHandle(handle); err != nil {
			return e.failErr(err)
		}
		if seen[handle] {
			return e.fail(ExitError, "two entries in %s map to the same handle %s", path, handle)
		}
		seen[handle] = true
		items = append(items, item{handle: handle, binding: en.Name, value: en.Value})
	}

	_, code := updateVault(e, func(v *vault.Vault) error {
		for _, it := range items {
			if _, err := v.Get(it.handle); err == nil {
				return fmt.Errorf("handle %s already exists in the Vault", it.handle)
			}
		}
		for _, it := range items {
			if _, err := v.Add(it.handle, it.value, vault.AddOptions{Binding: vault.Binding{Name: it.binding}}); err != nil {
				return err
			}
		}
		return nil
	})
	if code != ExitOK {
		return code
	}

	m, err := findOrNewManifest(".")
	if err != nil {
		return e.failErr(err)
	}
	for _, it := range items {
		m.Add(manifest.Entry{Handle: it.handle, Binding: vault.Binding{Name: it.binding}})
	}
	if err := m.Save(); err != nil {
		return e.failErr(err)
	}

	if !*keep {
		if err := shredFile(path); err != nil {
			return e.failErr(err)
		}
	}

	fprintf(e.stdout, "imported %d handle(s) from %s into %s\n", len(items), path, m.Path)
	return ExitOK
}

// normalizePrefix makes sure a non-empty Handle prefix ends in exactly one
// "/", so --prefix myapp and --prefix myapp/ behave the same.
func normalizePrefix(p string) string {
	if p == "" {
		return ""
	}
	return strings.TrimRight(p, "/") + "/"
}

// findOrNewManifest loads the Manifest reachable from dir, or prepares a new
// one at dir/.claudepass.toml if none exists yet.
func findOrNewManifest(dir string) (*manifest.Manifest, error) {
	p, err := manifest.Find(dir)
	if err != nil {
		if errors.Is(err, manifest.ErrNotFound) {
			return &manifest.Manifest{Path: filepath.Join(dir, manifest.FileName)}, nil
		}
		return nil, err
	}
	return manifest.Load(p)
}

// shredFile overwrites a regular file with zeros, syncs, and unlinks it.
func shredFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().IsRegular() && st.Size() > 0 {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		if _, err := f.Write(make([]byte, st.Size())); err != nil {
			_ = f.Close() // best-effort: the Write error above is what we report
			return err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close() // best-effort: the Sync error above is what we report
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return os.Remove(path)
}
