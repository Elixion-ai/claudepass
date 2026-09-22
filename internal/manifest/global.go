package manifest

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Elixion-ai/claudepass/internal/broker"
	"github.com/Elixion-ai/claudepass/internal/lockfile"
)

// GlobalFileName is the machine-wide Manifest, at the ClaudePass home
// alongside the Vault. It is the same format as a project's .claudepass.toml
// and, like it, holds no Secret values — only the Handles this machine
// declares for every project it has been introduced to.
const GlobalFileName = "global.toml"

// GlobalPath is where the Global Manifest lives.
func GlobalPath() (string, error) {
	home, err := broker.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, GlobalFileName), nil
}

// LoadGlobal reads the Global Manifest. A missing file is not an error, as
// it is for a project Manifest (ErrNotFound): declaring nothing globally is
// the ordinary state of a machine, not a misconfiguration, so callers get an
// empty Manifest they can Add to and SaveGlobal straight away.
func LoadGlobal() (*Manifest, error) {
	p, err := GlobalPath()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return &Manifest{Path: p, global: true}, nil
		}
		return nil, err
	}
	m, err := Load(p)
	if err != nil {
		return nil, err
	}
	m.global = true
	return m, nil
}

// SaveGlobal writes the Global Manifest, creating the ClaudePass home if it
// does not exist yet (0700, matching the Vault's own directory mode — the
// file itself is 0644 like any Manifest, since it carries no values) and
// tightening it to 0700 even if it already existed looser (CLA-98).
func (m *Manifest) SaveGlobal() error {
	if err := ensurePrivateDir(filepath.Dir(m.Path)); err != nil {
		return err
	}
	m.global = true
	return m.Save()
}

// UpdateGlobal is the one correct way for a `cpass` process to change the
// Global Manifest: it holds an exclusive lock (internal/lockfile) for the
// whole cycle, loads it fresh under that lock, runs fn, and SaveGlobals the
// result if fn returns nil. `cpass global`, `cpass add -g`, `cpass local`
// and `cpass manifest add -g` all funnel through this so two `cpass`
// processes declaring or undeclaring a Handle at once can never race each
// other's LoadGlobal -> mutate -> SaveGlobal and silently drop one of their
// declarations (CLA-93).
func UpdateGlobal(fn func(m *Manifest) error) (*Manifest, error) {
	p, err := GlobalPath()
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(filepath.Dir(p)); err != nil {
		return nil, err
	}
	lock, err := lockfile.Acquire(p+".lock", lockfile.DefaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("manifest: locking the Global Manifest for write: %w", err)
	}
	defer func() { _ = lock.Release() }()
	m, err := LoadGlobal()
	if err != nil {
		return nil, err
	}
	if err := fn(m); err != nil {
		return nil, err
	}
	if err := m.SaveGlobal(); err != nil {
		return nil, err
	}
	return m, nil
}
