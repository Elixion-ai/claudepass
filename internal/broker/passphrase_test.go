package broker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
