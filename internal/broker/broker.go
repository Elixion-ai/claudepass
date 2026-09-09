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
