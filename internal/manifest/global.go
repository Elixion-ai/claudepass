package manifest

import (
	"os"
	"path/filepath"

	"github.com/Elixion-ai/claudepass/internal/broker"
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
// file itself is 0644 like any Manifest, since it carries no values).
func (m *Manifest) SaveGlobal() error {
	if err := os.MkdirAll(filepath.Dir(m.Path), 0o700); err != nil {
		return err
	}
	m.global = true
	return m.Save()
}
