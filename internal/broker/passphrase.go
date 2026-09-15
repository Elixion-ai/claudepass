package broker

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

// Scrypt parameters for deriving the wrapping key from a master passphrase.
// N=2^15, r=8, p=1 are the interactive-login parameters recommended by
// golang.org/x/crypto/scrypt: well under a second on ordinary hardware.
const (
	scryptN   = 1 << 15
	scryptR   = 8
	scryptP   = 1
	saltBytes = 16
)

func saltPath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "broker.salt"), nil
}

// loadOrCreateSalt returns the salt used to derive the passphrase key,
// creating and persisting a fresh random one under CPASS_HOME on first use.
func loadOrCreateSalt() ([]byte, error) {
	p, err := saltPath()
	if err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(p); err == nil {
		if len(b) != saltBytes {
			return nil, fmt.Errorf("broker: salt file %s is corrupt (want %d bytes, got %d)", p, saltBytes, len(b))
		}
		return b, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("broker: entropy: %w", err)
	}
	if err := os.WriteFile(p, salt, 0o600); err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveKey scrypt-derives the Vault unlock key from a master passphrase and
// the salt persisted under CPASS_HOME. The same passphrase always yields the
// same key, so cpass init (which picks the key) and cpass unlock (which
// reproduces it) agree without the passphrase ever being stored.
func DeriveKey(passphrase string) ([]byte, error) {
	salt, err := loadOrCreateSalt()
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, vault.KeySize)
	if err != nil {
		return nil, fmt.Errorf("broker: derive key: %w", err)
	}
	return key, nil
}
