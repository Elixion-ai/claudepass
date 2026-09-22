package broker

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

// withHome points CPASS_HOME at a fresh, empty temp directory for the
// duration of the test.
func withHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(EnvHome, dir)
	return dir
}

// TestDeriveKeyUsesRaisedParamsForNewDerivations covers CLA-57's core fix: a
// passphrase derived for the first time on a machine (no broker.salt yet)
// must use the raised, offline-resistant scrypt cost, and must persist that
// cost next to the salt rather than leave it to be guessed later.
func TestDeriveKeyUsesRaisedParamsForNewDerivations(t *testing.T) {
	dir := withHome(t)

	key1, err := DeriveKey("correct horse battery staple")
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	if len(key1) != vault.KeySize {
		t.Fatalf("key length = %d, want %d", len(key1), vault.KeySize)
	}

	kb, err := os.ReadFile(filepath.Join(dir, kdfFileName))
	if err != nil {
		t.Fatalf("read %s: %v", kdfFileName, err)
	}
	var params kdfParams
	if err := json.Unmarshal(kb, &params); err != nil {
		t.Fatalf("unmarshal %s: %v", kdfFileName, err)
	}
	if params.N != scryptN || params.R != scryptR || params.P != scryptP {
		t.Fatalf("persisted params = %+v, want N=%d R=%d P=%d", params, scryptN, scryptR, scryptP)
	}
	if params == (kdfParams{N: legacyScryptN, R: legacyScryptR, P: legacyScryptP}) {
		t.Fatal("a fresh derivation persisted the legacy (login-speed) parameters, not the raised ones")
	}

	// The same passphrase against the now-persisted salt and params must
	// reproduce the same key (cpass init and cpass unlock must agree).
	key2, err := DeriveKey("correct horse battery staple")
	if err != nil {
		t.Fatalf("DeriveKey (second call): %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatal("DeriveKey is not reproducible for the same passphrase and persisted salt/params")
	}
}

// TestDeriveKeyLegacyFixtureStillUnlocks reproduces a Vault initialised
// before this fix: a broker.salt file with no broker.kdf record next to it.
// DeriveKey must still derive the exact key the old N=2^15 code would have
// produced, so an existing passphrase Vault keeps unlocking with the same
// passphrase.
func TestDeriveKeyLegacyFixtureStillUnlocks(t *testing.T) {
	dir := withHome(t)

	legacySalt := []byte("0123456789abcdef") // 16 bytes, the legacy saltBytes size
	if len(legacySalt) != saltBytes {
		t.Fatalf("test fixture salt is %d bytes, want %d", len(legacySalt), saltBytes)
	}
	if err := os.WriteFile(filepath.Join(dir, "broker.salt"), legacySalt, 0o600); err != nil {
		t.Fatalf("write legacy salt fixture: %v", err)
	}
	// Deliberately no broker.kdf: that absence is what marks this salt as
	// legacy.

	want, err := scrypt.Key([]byte("hunter2 hunter2"), legacySalt, legacyScryptN, legacyScryptR, legacyScryptP, vault.KeySize)
	if err != nil {
		t.Fatalf("reference scrypt.Key: %v", err)
	}

	got, err := DeriveKey("hunter2 hunter2")
	if err != nil {
		t.Fatalf("DeriveKey against legacy fixture: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("DeriveKey did not reproduce the legacy N=2^15 key for a pre-existing broker.salt with no broker.kdf record")
	}

	// The legacy fixture must not have been silently upgraded in place:
	// loadOrCreateParams only ever creates a broker.kdf record for a salt it
	// creates itself.
	if _, err := os.Stat(filepath.Join(dir, kdfFileName)); !os.IsNotExist(err) {
		t.Fatalf("expected no %s to be written next to a legacy salt, stat err = %v", kdfFileName, err)
	}
}

// TestLoadOrCreateParamsNeverLeavesOrphanedSaltOnInterruption covers CLA-57:
// an interruption between the two files loadOrCreateParams persists (a
// crash, Ctrl-C, power loss, a disk-full error) must never leave
// broker.salt on disk without a matching broker.kdf next to it, because
// DeriveKey treats that exact on-disk shape as a genuine pre-existing
// (legacy) Vault and silently re-derives with the weak N=2^15 parameters
// forever (see TestDeriveKeyLegacyFixtureStillUnlocks) — indistinguishable
// from a vault this project itself just started creating.
//
// Blocking the broker.kdf write (by pre-creating its path as a directory,
// so any os.WriteFile there fails with "is a directory") stands in for any
// interruption between the two writes, regardless of which one physically
// happens first: an implementation that writes broker.salt before
// broker.kdf gets past the salt write untouched and leaves the
// (unrecoverable, permanently-legacy) salt-without-kdf shape behind: an
// implementation that writes broker.kdf first never gets far enough to
// write broker.salt at all, so the only residue is a cleanly retryable
// "neither file exists yet".
func TestLoadOrCreateParamsNeverLeavesOrphanedSaltOnInterruption(t *testing.T) {
	dir := withHome(t)

	kp := filepath.Join(dir, kdfFileName)
	if err := os.Mkdir(kp, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := DeriveKey("interrupted derivation"); err == nil {
		t.Fatal("DeriveKey should have failed while broker.kdf could not be written")
	}

	sp := filepath.Join(dir, "broker.salt")
	if _, err := os.Stat(sp); err == nil {
		t.Fatal("broker.salt was written before broker.kdf; an interruption right after this point leaves " +
			"a salt with no kdf record, which DeriveKey silently and permanently treats as a legacy vault (CLA-57)")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat broker.salt: %v", err)
	}

	// Clear the obstruction and retry, as a user re-running `cpass init`
	// after the interruption would: this must land on the raised
	// parameters, never fall back to legacy because of the earlier failed
	// attempt.
	if err := os.Remove(kp); err != nil {
		t.Fatal(err)
	}
	key, err := DeriveKey("interrupted derivation")
	if err != nil {
		t.Fatalf("DeriveKey after clearing the obstruction: %v", err)
	}
	if len(key) != vault.KeySize {
		t.Fatalf("key length = %d, want %d", len(key), vault.KeySize)
	}
	kb, err := os.ReadFile(kp)
	if err != nil {
		t.Fatalf("read %s: %v", kdfFileName, err)
	}
	var params kdfParams
	if err := json.Unmarshal(kb, &params); err != nil {
		t.Fatalf("unmarshal %s: %v", kdfFileName, err)
	}
	if params.N != scryptN || params.R != scryptR || params.P != scryptP {
		t.Fatalf("persisted params after retry = %+v, want the raised N=%d R=%d P=%d, not a silent legacy fallback",
			params, scryptN, scryptR, scryptP)
	}
}

// TestDeriveKeyTightensExistingDirPermissions covers CLA-58: a CPASS_HOME
// that already exists (e.g. left at 0755 by a stray umask, or simply reused
// across cpass versions) must be tightened to 0700, not left as-is because
// MkdirAll is a no-op on a directory that already exists.
func TestDeriveKeyTightensExistingDirPermissions(t *testing.T) {
	dir := withHome(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := DeriveKey("whatever whatever"); err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("CPASS_HOME mode = %v, want 0700", st.Mode().Perm())
	}
}

// TestDeriveKeyCorruptSalt covers the pre-existing corrupt-salt-length
// error path, now routed through loadOrCreateParams instead of
// loadOrCreateSalt.
func TestDeriveKeyCorruptSalt(t *testing.T) {
	dir := withHome(t)
	if err := os.WriteFile(filepath.Join(dir, "broker.salt"), []byte("too-short"), 0o600); err != nil {
		t.Fatalf("write corrupt salt fixture: %v", err)
	}
	if _, err := DeriveKey("whatever"); err == nil {
		t.Fatal("DeriveKey did not error on a corrupt-length salt file")
	}
}

// TestDeriveKeyCorruptKdf covers a broker.kdf record that fails to parse
// next to an otherwise-valid salt.
func TestDeriveKeyCorruptKdf(t *testing.T) {
	dir := withHome(t)
	if err := os.WriteFile(filepath.Join(dir, "broker.salt"), []byte("0123456789abcdef"), 0o600); err != nil {
		t.Fatalf("write salt fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, kdfFileName), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write corrupt kdf fixture: %v", err)
	}
	if _, err := DeriveKey("whatever"); err == nil {
		t.Fatal("DeriveKey did not error on a corrupt broker.kdf record")
	}
}

// BenchmarkDeriveKey measures a single derivation's wall time at the current
// (raised) parameters. Not a pass/fail assertion — timing on a shared CI
// runner is not a reliable thing to assert on — but `go test -bench
// BenchmarkDeriveKey -benchtime=1x` is how docs/SECURITY.md's stated
// derivation time was produced, and reproducing it after any future
// parameter change is one command.
func BenchmarkDeriveKey(b *testing.B) {
	dir := b.TempDir()
	b.Setenv(EnvHome, dir)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DeriveKey("correct horse battery staple"); err != nil {
			b.Fatal(err)
		}
		// Only the first iteration's derivation is at the raised cost from
		// scratch; DeriveKey's own reproducibility (proven above) makes
		// every call after the first do identical work, so b.N > 1 still
		// measures the real per-derivation cost, just against a
		// pre-persisted salt from the second iteration on.
	}
}

// legacyFixture builds a passphrase Vault the way CLA-57's original code
// would have: a 16-byte broker.salt with no broker.kdf record next to it,
// wrapped under a key derived with the legacy N=2^15 parameters. Mirrors
// TestDeriveKeyLegacyFixtureStillUnlocks' own fixture, factored out for
// CLA-97's upgrade tests below, and seeds one Handle so a test can confirm
// an upgrade never touches Vault data.
func legacyFixture(t *testing.T, dir, passphrase string) (path string, salt, legacyKey []byte) {
	t.Helper()
	salt = []byte("0123456789abcdef")
	if len(salt) != saltBytes {
		t.Fatalf("test fixture salt is %d bytes, want %d", len(salt), saltBytes)
	}
	if err := os.WriteFile(filepath.Join(dir, "broker.salt"), salt, 0o600); err != nil {
		t.Fatalf("write legacy salt fixture: %v", err)
	}
	legacyKey, err := scrypt.Key([]byte(passphrase), salt, legacyScryptN, legacyScryptR, legacyScryptP, vault.KeySize)
	if err != nil {
		t.Fatalf("reference scrypt.Key: %v", err)
	}
	path = filepath.Join(dir, "vault.cpv")
	v, err := vault.Create(path, legacyKey)
	if err != nil {
		t.Fatalf("vault.Create legacy fixture: %v", err)
	}
	if _, err := v.Add("fixture/handle", "fixture-value-long-enough", vault.AddOptions{}); err != nil {
		t.Fatalf("seed legacy fixture with a Handle: %v", err)
	}
	if err := v.Save(); err != nil {
		t.Fatalf("save legacy fixture: %v", err)
	}
	v.Close()
	return path, salt, legacyKey
}

// TestUnlockPassphraseUpgradesLegacyVaultOnSuccessfulUnlock is CLA-97's core
// acceptance test: a legacy fixture (16-byte broker.salt, Vault wrapped
// under an N=2^15-derived key) unlocks with the same passphrase, and
// afterwards broker.kdf records the current parameters and the Vault still
// opens — with every Handle it had before, untouched. A second unlock is a
// no-op: no further upgrade, same key, nothing rewritten.
func TestUnlockPassphraseUpgradesLegacyVaultOnSuccessfulUnlock(t *testing.T) {
	dir := withHome(t)
	const passphrase = "correct horse battery staple"
	path, salt, legacyKey := legacyFixture(t, dir, passphrase)

	key, upgraded, err := UnlockPassphrase(path, passphrase)
	if err != nil {
		t.Fatalf("UnlockPassphrase: %v", err)
	}
	if !upgraded {
		t.Fatal("a legacy Vault's first successful unlock must report an upgrade")
	}

	wantKey, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, vault.KeySize)
	if err != nil {
		t.Fatalf("reference scrypt.Key: %v", err)
	}
	if string(key) != string(wantKey) {
		t.Fatal("UnlockPassphrase did not return the current-parameters key")
	}

	kb, err := os.ReadFile(filepath.Join(dir, kdfFileName))
	if err != nil {
		t.Fatalf("read %s: %v", kdfFileName, err)
	}
	var params kdfParams
	if err := json.Unmarshal(kb, &params); err != nil {
		t.Fatalf("unmarshal %s: %v", kdfFileName, err)
	}
	if params != currentParams() {
		t.Fatalf("persisted params = %+v, want %+v", params, currentParams())
	}

	if _, err := vault.Open(path, legacyKey); !errors.Is(err, vault.ErrWrongKey) {
		t.Fatalf("Open with the pre-upgrade (legacy) key after unlock = %v, want ErrWrongKey", err)
	}
	v, err := vault.Open(path, key)
	if err != nil {
		t.Fatalf("Open with the post-upgrade key: %v", err)
	}
	e, err := v.Get("fixture/handle")
	v.Close()
	if err != nil || e.Value != "fixture-value-long-enough" {
		t.Fatalf("upgrade must not touch Entries: got %+v, %v", e, err)
	}

	key2, upgraded2, err := UnlockPassphrase(path, passphrase)
	if err != nil {
		t.Fatalf("second UnlockPassphrase: %v", err)
	}
	if upgraded2 {
		t.Fatal("an already-current Vault must not report an upgrade again")
	}
	if string(key2) != string(key) {
		t.Fatal("second UnlockPassphrase returned a different key for the same passphrase")
	}
}

// TestUnlockPassphraseAlreadyCurrentNeverUpgrades covers the common case
// (a Vault initialised after CLA-57, never legacy at all): UnlockPassphrase
// must not report an upgrade or touch broker.kdf when the persisted
// parameters already match currentParams.
func TestUnlockPassphraseAlreadyCurrentNeverUpgrades(t *testing.T) {
	dir := withHome(t)
	const passphrase = "already current passphrase"
	// DeriveKey's own first call creates a fresh, already-current salt/kdf
	// pair (TestDeriveKeyUsesRaisedParamsForNewDerivations) — reuse that to
	// build the fixture rather than duplicating loadOrCreateParams' own
	// fresh-generation logic here.
	key0, err := DeriveKey(passphrase)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	path := filepath.Join(dir, "vault.cpv")
	v, err := vault.Create(path, key0)
	if err != nil {
		t.Fatalf("vault.Create: %v", err)
	}
	v.Close()

	kb1, err := os.ReadFile(filepath.Join(dir, kdfFileName))
	if err != nil {
		t.Fatalf("read %s: %v", kdfFileName, err)
	}

	key, upgraded, err := UnlockPassphrase(path, passphrase)
	if err != nil {
		t.Fatalf("UnlockPassphrase: %v", err)
	}
	if upgraded {
		t.Fatal("an already-current Vault must not report an upgrade")
	}
	if string(key) != string(key0) {
		t.Fatal("UnlockPassphrase returned a different key than the already-current derivation")
	}
	kb2, err := os.ReadFile(filepath.Join(dir, kdfFileName))
	if err != nil {
		t.Fatalf("read %s after unlock: %v", kdfFileName, err)
	}
	if string(kb1) != string(kb2) {
		t.Fatal("an already-current unlock must not rewrite broker.kdf")
	}
}

// TestUnlockPassphraseWrongPassphraseRefusedEvenWhenStale confirms the
// stale-parameters retry (deriveAndValidate) never turns into a way to
// bypass a wrong passphrase: both the legacy-parameters attempt and the
// current-parameters fallback must fail for a genuinely wrong passphrase,
// and nothing gets upgraded or written on a refused unlock.
func TestUnlockPassphraseWrongPassphraseRefusedEvenWhenStale(t *testing.T) {
	dir := withHome(t)
	path, _, _ := legacyFixture(t, dir, "right passphrase")

	if _, _, err := UnlockPassphrase(path, "wrong passphrase"); err == nil {
		t.Fatal("UnlockPassphrase must refuse a wrong passphrase even against a stale-parameters Vault")
	}
	if _, err := os.Stat(filepath.Join(dir, kdfFileName)); !os.IsNotExist(err) {
		t.Fatalf("a refused unlock must not write %s", kdfFileName)
	}
}

// TestUnlockPassphraseSurvivesCrashBetweenRewrapAndKDFPersist is CLA-97's
// crash-safety proof. afterVaultRewrap is this package's test hook (see its
// doc comment, mirroring internal/atomicfile's syncObserver): set here to
// unwind the calling goroutine — the closest a Go test can get to a real
// process crash — at the exact point between the Vault's re-wrap (already
// durable) and broker.kdf recording it (not yet attempted). The residue
// left behind must still unlock with the same passphrase, and a later,
// uninterrupted call must finish the upgrade rather than leave it
// half-done forever.
func TestUnlockPassphraseSurvivesCrashBetweenRewrapAndKDFPersist(t *testing.T) {
	dir := withHome(t)
	const passphrase = "crash-test passphrase"
	path, _, legacyKey := legacyFixture(t, dir, passphrase)

	prev := afterVaultRewrap
	defer func() { afterVaultRewrap = prev }()

	var rewrapped sync.WaitGroup
	rewrapped.Add(1)
	afterVaultRewrap = func() {
		rewrapped.Done()
		runtime.Goexit() // simulate the process dying right here
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = UnlockPassphrase(path, passphrase)
	}()
	rewrapped.Wait() // the hook fired: the Vault re-wrap is already durable
	<-done           // the goroutine has fully unwound past the hook

	if _, err := os.Stat(filepath.Join(dir, kdfFileName)); !os.IsNotExist(err) {
		t.Fatalf("simulated crash should have left no %s behind yet", kdfFileName)
	}
	if _, err := vault.Open(path, legacyKey); !errors.Is(err, vault.ErrWrongKey) {
		t.Fatalf("Vault should already be re-wrapped after the simulated crash: Open(legacyKey) = %v, want ErrWrongKey", err)
	}

	afterVaultRewrap = nil
	key, upgraded, err := UnlockPassphrase(path, passphrase)
	if err != nil {
		t.Fatalf("UnlockPassphrase after simulated crash did not still unlock with the same passphrase: %v", err)
	}
	if !upgraded {
		t.Fatal("the retry must still report finishing the interrupted upgrade")
	}
	kb, err := os.ReadFile(filepath.Join(dir, kdfFileName))
	if err != nil {
		t.Fatalf("read %s after retry: %v", kdfFileName, err)
	}
	var params kdfParams
	if err := json.Unmarshal(kb, &params); err != nil {
		t.Fatalf("unmarshal %s: %v", kdfFileName, err)
	}
	if params != currentParams() {
		t.Fatalf("persisted params after retry = %+v, want %+v", params, currentParams())
	}
	v, err := vault.Open(path, key)
	if err != nil {
		t.Fatalf("Open with the retry's key: %v", err)
	}
	v.Close()
}

// TestDeriveKeyRefusesOutOfBoundsKDFParams covers CLA-97's bound on a
// broker.kdf record read from disk: N must be a power of two in
// [2^15, 2^20], r <= 32, p <= 16. Each case must fail fast — well under the
// ~330ms a legitimate derivation takes, let alone the time scrypt.Key would
// spend actually trying to honour an N=2^30 — proving the bound is checked
// before ever reaching scrypt.Key, not as a slow failure from within it.
func TestDeriveKeyRefusesOutOfBoundsKDFParams(t *testing.T) {
	cases := []struct {
		name   string
		params kdfParams
	}{
		{"n above the max", kdfParams{N: 1 << 30, R: 8, P: 1}},
		{"n below the legacy floor", kdfParams{N: 1 << 10, R: 8, P: 1}},
		{"n not a power of two", kdfParams{N: 200000, R: 8, P: 1}},
		{"r above the max", kdfParams{N: scryptN, R: 64, P: 1}},
		{"r zero", kdfParams{N: scryptN, R: 0, P: 1}},
		{"p above the max", kdfParams{N: scryptN, R: 8, P: 32}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := withHome(t)
			if err := os.WriteFile(filepath.Join(dir, "broker.salt"), []byte("0123456789abcdef"), 0o600); err != nil {
				t.Fatalf("write salt fixture: %v", err)
			}
			b, err := json.Marshal(tc.params)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, kdfFileName), b, 0o600); err != nil {
				t.Fatalf("write kdf fixture: %v", err)
			}
			start := time.Now()
			if _, err := DeriveKey("whatever"); err == nil {
				t.Fatal("DeriveKey should have refused an out-of-bounds broker.kdf record")
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("DeriveKey took %s to refuse %+v — the bound must be checked before scrypt.Key ever runs, not discovered by running it", elapsed, tc.params)
			}
		})
	}
}
