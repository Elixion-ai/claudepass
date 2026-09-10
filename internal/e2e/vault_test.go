package e2e

import (
	"os"
	"strings"
	"testing"
)

const secret = "sk_live_51H8xTESTVALUE9zQ2"

func TestInitAddLsNeverPrintsValue(t *testing.T) {
	ve := newVault(t)
	if r := ve.add("stripe/live", secret); r.code != 0 {
		t.Fatalf("add: %s", r)
	}
	r := ve.run(nil, "ls")
	if r.code != 0 || strings.TrimSpace(r.stdout) != "stripe/live" {
		t.Fatalf("ls: %s", r)
	}
	if strings.Contains(r.stdout+r.stderr, secret) {
		t.Fatalf("ls leaked the value: %s", r)
	}
	r = ve.run(nil, "ls", "-l")
	if !strings.Contains(r.stdout, "env STRIPE_LIVE") {
		t.Fatalf("ls -l should show default Binding: %s", r)
	}
	if strings.Contains(r.stdout, secret) {
		t.Fatalf("ls -l leaked the value: %s", r)
	}
}

func TestVaultFileNeverContainsPlaintext(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", secret)
	raw, err := os.ReadFile(ve.vaultPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "stripe/live") {
		t.Fatal("vault file contains plaintext")
	}
	st, _ := os.Stat(ve.vaultPath())
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("vault mode %v, want 0600", st.Mode().Perm())
	}
}

func TestWrongKeyIsRefused(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", secret)
	other := newVault(t) // just for a different key
	ve.key = other.key
	r := ve.run(nil, "ls")
	if r.code == 0 || !strings.Contains(r.stderr, "wrong key") {
		t.Fatalf("want wrong-key error: %s", r)
	}
}

func TestTamperedVaultIsRefused(t *testing.T) {
	ve := newVault(t)
	ve.add("stripe/live", secret)
	raw, _ := os.ReadFile(ve.vaultPath())
	// Flip a byte inside the ciphertext field.
	i := strings.Index(string(raw), `"ciphertext": "`) + len(`"ciphertext": "`) + 5
	b := []byte(string(raw))
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if err := os.WriteFile(ve.vaultPath(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	r := ve.run(nil, "ls")
	if r.code == 0 || !strings.Contains(r.stderr, "tampered") {
		t.Fatalf("want tamper error: %s", r)
	}
}

func TestShortValueRefused(t *testing.T) {
	ve := newVault(t)
	r := ve.add("short/one", "abcde")
	if r.code == 0 || !strings.Contains(r.stderr, "shorter than 8") {
		t.Fatalf("want short-value refusal: %s", r)
	}
}

func TestAddWithoutTerminalRefusesAndPointsAtCapture(t *testing.T) {
	ve := newVault(t)
	// No CPASS_TEST_STDIN: stdin is a pipe, not a terminal.
	r := ve.runEnv(nil, nil, "add", "x/y")
	if r.code == 0 || !strings.Contains(r.stderr, "cpass capture") {
		t.Fatalf("want refusal pointing at capture: %s", r)
	}
}

func TestRmAndMv(t *testing.T) {
	ve := newVault(t)
	ve.add("a/one", "value-number-one")
	ve.add("a/two", "value-number-two")
	if r := ve.run(nil, "mv", "a/one", "b/one"); r.code != 0 {
		t.Fatalf("mv: %s", r)
	}
	if r := ve.run(nil, "rm", "a/two"); r.code != 0 {
		t.Fatalf("rm: %s", r)
	}
	r := ve.run(nil, "ls", "-l")
	if !strings.Contains(r.stdout, "b/one") || strings.Contains(r.stdout, "a/") {
		t.Fatalf("ls after mv/rm: %s", r)
	}
	if !strings.Contains(r.stdout, "B_ONE") {
		t.Fatalf("default Binding should follow the rename: %s", r)
	}
	if r := ve.run(nil, "rm", "nope/none"); r.code == 0 || !strings.Contains(r.stderr, "no such handle") {
		t.Fatalf("rm missing: %s", r)
	}
}

func TestBindingFlagsAndExposed(t *testing.T) {
	ve := newVault(t)
	ve.add("gcp/sa", "{\"type\":\"service_account\"}", "--file", "--binding", "GOOGLE_APPLICATION_CREDENTIALS")
	ve.add("seen/one", "already-seen-value", "--exposed")
	r := ve.run(nil, "ls", "-l")
	if !strings.Contains(r.stdout, "file GOOGLE_APPLICATION_CREDENTIALS") {
		t.Fatalf("file binding: %s", r)
	}
	if !strings.Contains(r.stdout, "seen/one") || !strings.Contains(r.stdout, "EXPOSED") {
		t.Fatalf("exposed flag: %s", r)
	}
	r = ve.run(nil, "ls", "--exposed")
	if strings.TrimSpace(r.stdout) != "seen/one" {
		t.Fatalf("ls --exposed: %s", r)
	}
}

func TestInvalidHandle(t *testing.T) {
	ve := newVault(t)
	r := ve.add("Bad Handle", "some-long-value")
	if r.code == 0 || !strings.Contains(r.stderr, "invalid handle") {
		t.Fatalf("want invalid handle: %s", r)
	}
}

func TestLockedVaultFailsFast(t *testing.T) {
	ve := newVault(t)
	ve.key = ""
	r := ve.run(nil, "ls")
	if r.code == 0 || !strings.Contains(r.stderr, "locked") {
		t.Fatalf("want locked error: %s", r)
	}
}
