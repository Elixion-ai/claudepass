package broker

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"

	"github.com/Elixion-ai/claudepass/internal/atomicfile"
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
// keeps reporting them until UnlockPassphrase's transparent upgrade (CLA-97)
// re-derives and re-wraps it onto the current parameters, on the next
// successful passphrase unlock — see UnlockPassphrase's doc comment.
const (
	scryptN = 1 << 18
	scryptR = 8
	scryptP = 1

	legacyScryptN = 1 << 15
	legacyScryptR = 8
	legacyScryptP = 1

	saltBytes = 16
)

// minScryptN/maxScryptN/maxScryptR/maxScryptP bound a broker.kdf record
// read from disk (CLA-97). Writing that file already requires the
// same-user access docs/THREATS.md places out of scope — this is defence
// in depth, not a response to a realistic external attacker: a
// syntactically valid but extreme N (2^30, say) handed straight to
// scrypt.Key would try to allocate on the order of a terabyte and hang
// rather than fail. minScryptN is this project's own legacy floor
// (legacyScryptN); maxScryptN keeps a future cost increase inside the
// >=250ms/<=256MiB offline-resistant-but-CI-safe target documented in
// docs/SECURITY.md and scryptN's own doc comment above (2^20 would already
// need 1GiB, so this bound exists to reject values past that, not to
// invite using it).
const (
	minScryptN = legacyScryptN
	maxScryptN = 1 << 20
	maxScryptR = 32
	maxScryptP = 16

	// maxScryptNR bounds N*r jointly, on top of maxScryptN and maxScryptR
	// above (2026-09-22 review of this ticket). scrypt's memory cost is
	// ~128*N*r bytes, so those two bounds alone still let a broker.kdf
	// record combine maxScryptN (already ~1GiB on its own — see its
	// comment above) with maxScryptR to reach ~4GiB, well past what either
	// bound individually intends to allow. maxScryptNR pins the ceiling at
	// maxScryptN's own memory cost at the standard r=8 (scryptR): any
	// combination within the individual bounds above that would cost more
	// than that — such as maxScryptN with a large r, or a large N with
	// maxScryptR — is rejected too.
	maxScryptNR = maxScryptN * scryptR
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

// currentParams is the target every new derivation, and every upgrade of an
// existing one (CLA-97), aims for.
func currentParams() kdfParams {
	return kdfParams{N: scryptN, R: scryptR, P: scryptP}
}

// validateParams bounds a kdfParams record (see the min/maxScrypt*
// constants' doc comment) before it is ever handed to scrypt.Key. Callers
// that read it from broker.kdf wrap the error with that file's path.
func validateParams(p kdfParams) error {
	if p.N < minScryptN || p.N > maxScryptN || p.N&(p.N-1) != 0 {
		return fmt.Errorf("n=%d is not a power of two in [2^15, 2^20]", p.N)
	}
	if p.R < 1 || p.R > maxScryptR {
		return fmt.Errorf("r=%d is out of bounds (want 1-%d)", p.R, maxScryptR)
	}
	if p.P < 1 || p.P > maxScryptP {
		return fmt.Errorf("p=%d is out of bounds (want 1-%d)", p.P, maxScryptP)
	}
	if p.N*p.R > maxScryptNR {
		return fmt.Errorf("n=%d and r=%d together cost too much memory (n*r=%d, want <=%d)", p.N, p.R, p.N*p.R, maxScryptNR)
	}
	return nil
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
// until something upgrades it. This function itself never does that
// in-place upgrade — raising N changes the derived key, which needs the
// Vault's data key re-wrapped under the new one to take effect, and that is
// a Vault-level operation this function (broker-only, no *vault.Vault in
// scope) has no business performing implicitly. UnlockPassphrase below is
// the one place that does, on the next successful passphrase unlock; see
// its doc comment, and docs/SECURITY.md for the on-disk sequence.
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
			if err := validateParams(params); err != nil {
				return nil, kdfParams{}, fmt.Errorf("broker: kdf file %s: %w", kp, err)
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
	params := kdfParams{N: scryptN, R: scryptR, P: scryptP}
	b, err := json.Marshal(params)
	if err != nil {
		return nil, kdfParams{}, err
	}
	kp, err := kdfPath()
	if err != nil {
		return nil, kdfParams{}, err
	}
	// broker.kdf before broker.salt, deliberately: if cpass is interrupted
	// (crash, Ctrl-C, power loss, a disk-full error) between the two
	// writes, the only residue a retry can ever find is "neither file
	// exists yet" — which lands right back in this same fresh-generation
	// branch — rather than "salt without kdf", which the branch above
	// treats as a genuine pre-existing (legacy) Vault and silently
	// re-derives with the weak N=2^15 parameters forever. Writing salt
	// first would let an interruption right after that write leave exactly
	// that indistinguishable, permanently-weak state behind.
	if err := os.WriteFile(kp, b, 0o600); err != nil {
		return nil, kdfParams{}, err
	}
	if err := os.WriteFile(sp, salt, 0o600); err != nil {
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
	return deriveWithParams(passphrase, salt, params)
}

// deriveWithParams is DeriveKey's actual scrypt call, factored out so
// UnlockPassphrase below can derive under a specific kdfParams (the
// persisted ones, or — mid-upgrade — the current target ones) without
// going through loadOrCreateParams' own read-or-create logic each time.
// Bounds p (validateParams) before ever handing it to scrypt.Key, even
// though every caller today already sources p from either a
// loadOrCreateParams call (which bounds it the same way) or currentParams()
// (a compile-time-safe constant): a second check this close to the actual
// allocation costs nothing and never trusts a future caller to have done
// it.
func deriveWithParams(passphrase string, salt []byte, p kdfParams) ([]byte, error) {
	if err := validateParams(p); err != nil {
		return nil, fmt.Errorf("broker: %w", err)
	}
	key, err := scrypt.Key([]byte(passphrase), salt, p.N, p.R, p.P, vault.KeySize)
	if err != nil {
		return nil, fmt.Errorf("broker: derive key: %w", err)
	}
	return key, nil
}

// afterVaultRewrap, when non-nil, is called by UnlockPassphrase immediately
// after the Vault has been durably re-wrapped under a newly derived key and
// before broker.kdf is written to record the parameters that produced it —
// the one point CLA-97's crash-safety requirement is about. Nothing in this
// package can portably simulate a real crash there, so this package's own
// tests set this to unwind the calling goroutine at exactly that point
// (mirroring internal/atomicfile's syncObserver, the same kind of
// test-only seam for an effect Go cannot otherwise observe or inject).
// Always nil in production.
var afterVaultRewrap func()

// UnlockPassphrase derives the Vault unlock key for passphrase, confirms it
// against the Vault at path (deriveAndValidate), and reports via upgraded
// whether this call performed — or, after an earlier interruption, finished
// — a transparent upgrade to the current KDF parameters, so the caller
// knows to print a one-line notice rather than stay silent.
//
// When the persisted KDF parameters are below currentParams, a successful
// unlock upgrades the Vault transparently: it re-derives the key under the
// current target parameters (same salt — see deriveAndValidate's doc
// comment for why the salt itself does not need to change), re-wraps the
// Vault's data key under that new derivation (rewrapForUpgrade, inside
// vault.Update's lock, so a concurrent writer can never interleave with it
// — CLA-55), and only once that Save has durably succeeded
// (internal/atomicfile, fsynced — CLA-56) persists the new parameters to
// broker.kdf (persistCurrentParams, itself an atomicfile.Write so a torn
// write can never leave broker.kdf holding an unparsable record). That
// order, and never the reverse, is deliberate: a crash between the two
// writes leaves the Vault already rewrapped under the new key while
// broker.kdf still names the old (or, for a legacy Vault, no) parameters.
// deriveAndValidate's retry — derive with currentParams and try that
// instead, whenever the persisted parameters fail to open the Vault — is
// what makes exactly that residue still unlock with the same passphrase;
// running UnlockPassphrase again from there also finishes the interrupted
// upgrade rather than leaving it half-done forever, since it reaches this
// same "parameters are stale" branch either way.
//
// Two concurrent UnlockPassphrase calls against the same stale-parameter
// Vault, both given the correct passphrase, can also reach this point with
// the same problem (2026-09-22 review): deriveAndValidate's derive-and-open
// happens outside vault.Update's lock, so both calls can validate against
// the still-legacy Vault before either has rewrapped it. Whichever loses
// the race to rewrapForUpgrade below finds the Vault already re-wrapped
// under the winner's (identically-derived, same-passphrase) key, and its
// own oldKey — correct when it was derived, stale by the time it is used —
// no longer opens it. See that call's own error handling for how this is
// told apart from a genuinely wrong passphrase and retried.
func UnlockPassphrase(path, passphrase string) (key []byte, upgraded bool, err error) {
	return unlockPassphrase(path, passphrase, true)
}

// unlockPassphrase is UnlockPassphrase's actual implementation. allowRetry
// is true on every real caller's entry point (UnlockPassphrase) and false
// only on the one recursive call this function makes itself, so a lost
// race (see UnlockPassphrase's doc comment) retries exactly once rather
// than risking a loop against some other, unanticipated reason
// rewrapForUpgrade might keep failing.
func unlockPassphrase(path, passphrase string, allowRetry bool) (key []byte, upgraded bool, err error) {
	key, salt, params, err := deriveAndValidate(path, passphrase)
	if err != nil {
		return nil, false, err
	}
	if params == currentParams() {
		return key, false, nil
	}

	newKey, err := deriveWithParams(passphrase, salt, currentParams())
	if err != nil {
		return nil, false, err
	}
	if err := rewrapForUpgrade(path, key, newKey); err != nil {
		if allowRetry && errors.Is(err, vault.ErrWrongKey) {
			// Lost the race described in UnlockPassphrase's doc comment:
			// by the time we reached vault.Update inside rewrapForUpgrade,
			// a concurrent call had already re-wrapped the Vault under its
			// own (same-passphrase) current-parameters key, so our key —
			// valid when deriveAndValidate confirmed it — no longer opens
			// the Vault. Re-deriving and re-validating from scratch finds
			// that already-upgraded Vault (deriveAndValidate's own
			// stale-params retry succeeds against it the same way it does
			// after a crash) rather than surfacing this timing as a
			// spurious wrong-passphrase failure for a passphrase that was
			// never wrong.
			zeroKey(key)
			zeroKey(newKey)
			return unlockPassphrase(path, passphrase, false)
		}
		return nil, false, fmt.Errorf("broker: upgrading this Vault's passphrase parameters: %w", err)
	}
	zeroKey(key) // superseded by newKey; CLA-60 hygiene, mirroring Rewrap's own.

	if afterVaultRewrap != nil {
		afterVaultRewrap()
	}

	if err := persistCurrentParams(); err != nil {
		// The Vault itself is already durably upgraded and usable with
		// newKey — only the on-disk record of that lags. Still reported as
		// an error rather than swallowed: a silently-partial upgrade would
		// hide a real problem (a full disk, a permissions change under
		// CPASS_HOME). The next successful UnlockPassphrase call finishes
		// this step; see the doc comment above.
		return newKey, true, fmt.Errorf("broker: vault upgraded but failed to record the new parameters: %w", err)
	}
	return newKey, true, nil
}

// deriveAndValidate derives the Vault unlock key for passphrase against
// whatever KDF parameters are currently persisted (loadOrCreateParams —
// legacy-implied or on-disk) and confirms it by actually opening the Vault
// at path.
//
// If that fails and the persisted parameters are stale, it retries once
// with currentParams before giving up: an earlier UnlockPassphrase call may
// have re-wrapped the Vault under the current-target-derived key and then
// been interrupted before persisting that fact (see UnlockPassphrase's doc
// comment), in which case the persisted (stale) parameters no longer open
// the Vault at all, only the current ones do. A genuinely wrong passphrase
// fails both attempts and reports the original error. Reusing the same
// persisted salt for that retry, rather than needing one of its own, is
// what makes the retry possible without anything extra having survived the
// interruption: raising N is what makes the old parameters offline-weak,
// not the salt, so upgrading only N/r/p (never rotating the salt) trades
// nothing away and keeps this recovery a pure function of information that
// was already durable before the upgrade ever started.
//
// The returned params is always what loadOrCreateParams actually found
// persisted on disk — never currentParams just because the fallback is
// what produced the working key. UnlockPassphrase's "does broker.kdf still
// need writing?" decision has to be about the disk, not about which
// derivation happened to open the Vault this time: after exactly the
// interruption above, the fallback key already is the current-params key,
// but broker.kdf still needs writing to say so — conflating the two would
// make UnlockPassphrase think there is nothing left to finish and leave
// that interrupted upgrade stuck half-done forever.
func deriveAndValidate(path, passphrase string) (key, salt []byte, params kdfParams, err error) {
	salt, params, err = loadOrCreateParams()
	if err != nil {
		return nil, nil, kdfParams{}, err
	}
	key, err = deriveWithParams(passphrase, salt, params)
	if err != nil {
		return nil, nil, kdfParams{}, err
	}
	if openErr := validateOpen(path, key); openErr != nil {
		if params != currentParams() {
			if altKey, altErr := deriveWithParams(passphrase, salt, currentParams()); altErr == nil {
				if validateOpen(path, altKey) == nil {
					return altKey, salt, params, nil
				}
			}
		}
		return nil, nil, kdfParams{}, openErr
	}
	return key, salt, params, nil
}

// validateOpen confirms key actually opens the Vault at path, without
// keeping it open: UnlockPassphrase's job ends at handing back a key that
// works, not at holding a *vault.Vault (StartBroker only ever wants the
// key itself).
func validateOpen(path string, key []byte) error {
	v, err := vault.Open(path, key)
	if err != nil {
		return err
	}
	v.Close()
	return nil
}

// rewrapForUpgrade re-wraps the Vault at path's data key under newKey,
// authenticating with oldKey first — vault.Update opens the Vault fresh
// under its own exclusive lock (CLA-55), so this is safe against a
// concurrent writer — and Saves durably (CLA-56) before returning.
// Deliberately does not touch broker.kdf/broker.salt itself: see
// UnlockPassphrase's doc comment for why that write happens separately,
// only after this one is confirmed durable.
func rewrapForUpgrade(path string, oldKey, newKey []byte) error {
	return vault.Update(path, oldKey, func(v *vault.Vault) error {
		return v.Rewrap(newKey)
	})
}

// persistCurrentParams overwrites broker.kdf with currentParams(),
// atomically (internal/atomicfile): a torn write here must never leave
// broker.kdf holding an unparsable record, since loadOrCreateParams treats
// that as a hard error rather than as a legacy fallback — worse than never
// having attempted the upgrade at all.
func persistCurrentParams() error {
	kp, err := kdfPath()
	if err != nil {
		return err
	}
	b, err := json.Marshal(currentParams())
	if err != nil {
		return err
	}
	return atomicfile.Write(kp, b, 0o600)
}
