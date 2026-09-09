// Package broker resolves Handles into Secret values at the moment a command
// runs. This slice provides the key source and Vault location; the unlock
// model (Keychain, Broker process) and Handle resolution build on it.
package broker

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"claudepass/internal/vault"
)

// EnvHome overrides the ClaudePass home directory.
const EnvHome = "CPASS_HOME"

// EnvKey supplies the unlock key directly (base64, 32 bytes). Used by CI and tests.
const EnvKey = "CPASS_KEY"

// ErrLocked is returned when no unlock key is available.
var ErrLocked = errors.New("vault is locked, run cpass unlock")

// Home returns the ClaudePass home directory, creating nothing.
func Home() (string, error) {
	if h := os.Getenv(EnvHome); h != "" {
		return h, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine config dir: %w", err)
	}
	return filepath.Join(dir, "claudepass"), nil
}

// VaultPath returns the path of the Vault file.
func VaultPath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "vault.cpv"), nil
}

// UnlockKey returns the unlock key from the environment. Later slices add
// the Keychain and Broker-process sources behind this same call.
func UnlockKey() ([]byte, error) {
	if s := os.Getenv(EnvKey); s != "" {
		k, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(k) != vault.KeySize {
			return nil, fmt.Errorf("%s must be base64 of %d bytes", EnvKey, vault.KeySize)
		}
		return k, nil
	}
	return nil, ErrLocked
}

// OpenVault opens the Vault with whatever unlock key is available.
func OpenVault() (*vault.Vault, error) {
	p, err := VaultPath()
	if err != nil {
		return nil, err
	}
	key, err := UnlockKey()
	if err != nil {
		return nil, err
	}
	return vault.Open(p, key)
}

// EnvCI forces CI mode: Handles resolve from the environment, no Vault.
const EnvCI = "CPASS_CI"

// CIMode reports whether Handles resolve from the environment instead of a
// Vault: CPASS_CI=1, or CI=true with no Vault file present.
func CIMode() bool {
	if os.Getenv(EnvCI) == "1" {
		return true
	}
	if os.Getenv(EnvCI) == "0" {
		return false
	}
	if os.Getenv("CI") == "true" {
		if p, err := VaultPath(); err == nil && !vault.Exists(p) {
			return true
		}
	}
	return false
}

// Ref names a Handle to inject, with an optional Binding-name override.
type Ref struct {
	Handle   string
	Override string // environment variable name; empty keeps the Handle's default
	// Declared is the Manifest's Binding for this Handle, if any. It wins
	// over the Vault's default Binding and is the only source in CI mode.
	Declared vault.Binding
}

// ParseRef parses "handle" or "handle:BINDING".
func ParseRef(s string) (Ref, error) {
	h, name, _ := strings.Cut(s, ":")
	if err := vault.ValidateHandle(h); err != nil {
		return Ref{}, err
	}
	if name != "" && !envNameRe.MatchString(name) {
		return Ref{}, fmt.Errorf("invalid binding name %q for %s", name, h)
	}
	return Ref{Handle: h, Override: name}, nil
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func resolveFromEnv(refs []Ref) ([]Resolved, error) {
	out := make([]Resolved, 0, len(refs))
	for _, r := range refs {
		name := r.Override
		if name == "" {
			name = r.Declared.Name
		}
		if name == "" {
			name = vault.DefaultBindingName(r.Handle)
		}
		val, ok := os.LookupEnv(name)
		if !ok {
			return nil, fmt.Errorf("CI mode: %s expects %s in the environment", r.Handle, name)
		}
		kind := r.Declared.Kind
		if kind == "" {
			kind = vault.BindEnv
		}
		out = append(out, Resolved{Handle: r.Handle, Value: val, Binding: vault.Binding{Kind: kind, Name: name}})
	}
	return out, nil
}

// Resolved is a Secret ready to inject.
type Resolved struct {
	Handle  string
	Value   string
	Binding vault.Binding
	Exposed bool
	// ExposedAt is when the Secret most recently became Exposed. Zero when
	// Exposed is false or the Vault carries no exposure history for it (CI
	// mode never sets this: there is no Vault to read it from).
	ExposedAt time.Time
}

// Resolve turns Refs into Secrets. It fails on the first missing Handle,
// naming it and nothing else. In CI mode each Handle resolves from the
// environment variable named by its Binding; refs must then carry the
// Binding (Override or Kind/Name via ResolveWithBindings).
func Resolve(refs []Ref) ([]Resolved, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	if CIMode() {
		return resolveFromEnv(refs)
	}
	v, err := OpenVault()
	if err != nil {
		return nil, err
	}
	out := make([]Resolved, 0, len(refs))
	for _, r := range refs {
		e, err := v.Get(r.Handle)
		if err != nil {
			return nil, fmt.Errorf("no such handle: %s", r.Handle)
		}
		b := e.Binding
		if r.Declared.Name != "" {
			b.Name = r.Declared.Name
		}
		if r.Declared.Kind != "" {
			b.Kind = r.Declared.Kind
		}
		if r.Override != "" {
			b.Name = r.Override
		}
		res := Resolved{Handle: e.Handle, Value: e.Value, Binding: b, Exposed: e.Exposed}
		if e.Exposed && len(e.Exposures) > 0 {
			res.ExposedAt = e.Exposures[len(e.Exposures)-1].At
		}
		out = append(out, res)
	}
	return out, nil
}
