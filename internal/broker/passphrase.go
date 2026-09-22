package broker

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

// Scrypt parameters for deriving the wrapping key from a master passphrase.
//
// N=2^18, r=8, p=1 are offline-resistant parameters: unlike a login prompt,
// broker.salt's own passphrase protects vault.cpv, a file an attacker who
// copies it can brute-force offline with unlimited parallel guesses, so the
// cost has to survive that rather than just feel instant to a human typing
// it once. Measured on ordinary current hardware (internal/broker/passphrase_test.go's
// BenchmarkDeriveKey, and see docs/SECURITY.md): ~330ms and 256MiB per
// derivation, both within the offline-resistant target of >=250ms and
// <=256MiB that stays safe on a small CI runner (N=2^20 would need 1GiB and
// risks OOMing one). Derivation happens once per `cpass unlock` or `cpass
// init` — the Broker then holds the derived key — so this cost is paid once
// per session, not per command.
//
// legacyScryptN/R/P are this project's original, too-weak, interactive-login
// parameters (well under a second, ~32MiB). A Vault whose broker.salt
// predates kdfFileName below was derived with them, and loadOrCreateParams
// keeps deriving it with them forever, so it keeps unlocking with the same
// passphrase — see that function's doc comment for why there is no in-place
// upgrade.
const (
	scryptN = 1 << 18
	scryptR = 8
	scryptP = 1

	legacyScryptN = 1 << 15
	legacyScryptR = 8
	legacyScryptP = 1

	saltBytes = 16
)

const kdfFileName = "broker.kdf"

// kdfParams is one derivation's scrypt cost, persisted next to the salt (see
// kdfPath) so that raising the cost again in the future never has to guess
// how an existing Vault's key was derived.
type kdfParams struct {
	N int `json:"n"`
	R int `json:"r"`
	P int `json:"p"`
}

func saltPath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "broker.salt"), nil
}

func kdfPath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, kdfFileName), nil
}

// loadOrCreateParams returns the salt and scrypt cost to derive the
// passphrase key with, creating and persisting a fresh random salt and the
// current (offline-resistant) parameters under CPASS_HOME on first use.
//
// An existing broker.salt with no broker.kdf record next to it predates
// that record: it was derived with the legacy, weaker parameters, and
// loadOrCreateParams keeps reporting those same legacy parameters for it
// indefinitely, so the same passphrase keeps reproducing the same key.
// There is deliberately no in-place upgrade here: raising N changes the
// derived key, which would need the Vault's data key re-wrapped under the
// new one to take effect, and that is a Vault-level operation this function
// (broker-only) has no business performing implicitly. See docs/SECURITY.md
// for how to move a passphrase Vault onto the new parameters today.
func loadOrCreateParams() ([]byte, kdfParams, error) {
	sp, err := saltPath()
	if err != nil {
		return nil, kdfParams{}, err
	}
	salt, err := os.ReadFile(sp)
	if err == nil {
		if len(salt) != saltBytes {
			return nil, kdfParams{}, fmt.Errorf("broker: salt file %s is corrupt (want %d bytes, got %d)", sp, saltBytes, len(salt))
		}
		kp, err := kdfPath()
		if err != nil {
			return nil, kdfParams{}, err
		}
		b, err := os.ReadFile(kp)
		if err == nil {
			var params kdfParams
			if jsonErr := json.Unmarshal(b, &params); jsonErr != nil {
				return nil, kdfParams{}, fmt.Errorf("broker: kdf file %s is corrupt: %w", kp, jsonErr)
			}
			return salt, params, nil
		}
		if !os.IsNotExist(err) {
			return nil, kdfParams{}, err
		}
		// Legacy: a salt file with no kdf record next to it.
		return salt, kdfParams{N: legacyScryptN, R: legacyScryptR, P: legacyScryptP}, nil
	} else if !os.IsNotExist(err) {
		return nil, kdfParams{}, err
	}

	dir := filepath.Dir(sp)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, kdfParams{}, err
	}
	// MkdirAll is a no-op on a directory that already exists, regardless of
	// its current mode, so a loosened CPASS_HOME would otherwise stay
	// loosened forever. Chmod unconditionally to make sure it ends up 0700
	// either way.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, kdfParams{}, err
	}
	salt = make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, kdfParams{}, fmt.Errorf("broker: entropy: %w", err)
	}
	if err := os.WriteFile(sp, salt, 0o600); err != nil {
		return nil, kdfParams{}, err
	}
	params := kdfParams{N: scryptN, R: scryptR, P: scryptP}
	b, err := json.Marshal(params)
	if err != nil {
		return nil, kdfParams{}, err
	}
	kp, err := kdfPath()
	if err != nil {
		return nil, kdfParams{}, err
	}
	if err := os.WriteFile(kp, b, 0o600); err != nil {
		return nil, kdfParams{}, err
	}
	return salt, params, nil
}

// DeriveKey scrypt-derives the Vault unlock key from a master passphrase and
// the salt persisted under CPASS_HOME, at whatever scrypt cost was recorded
// when that salt was created (see loadOrCreateParams). The same passphrase
// always yields the same key, so cpass init (which picks the key) and cpass
// unlock (which reproduces it) agree without the passphrase ever being
// stored.
func DeriveKey(passphrase string) ([]byte, error) {
	salt, params, err := loadOrCreateParams()
	if err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, params.N, params.R, params.P, vault.KeySize)
	if err != nil {
		return nil, fmt.Errorf("broker: derive key: %w", err)
	}
	return key, nil
}
