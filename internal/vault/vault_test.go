package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

func TestRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.cpv")
	v, err := Create(p, key(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Add("stripe/live", "sk_live_abcdefgh", AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Add("gcp/sa", "{\"type\":\"sa\"}", AddOptions{Binding: Binding{Kind: BindFile, Name: "GOOGLE_APPLICATION_CREDENTIALS"}}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}
	v2, err := Open(p, key(1))
	if err != nil {
		t.Fatal(err)
	}
	e, err := v2.Get("stripe/live")
	if err != nil || e.Value != "sk_live_abcdefgh" || e.Binding != (Binding{BindEnv, "STRIPE_LIVE"}) {
		t.Fatalf("got %+v, %v", e, err)
	}
	g, _ := v2.Get("gcp/sa")
	if g.Binding.Kind != BindFile {
		t.Fatalf("file binding lost: %+v", g)
	}
	if _, err := Open(p, key(2)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("want ErrWrongKey, got %v", err)
	}
}

// TestCloseZeroesKeyMaterial covers CLA-60: Close must zero both the unlock
// key and the data key a Vault holds in memory, and do so without
// corrupting the caller's own key slice — Open/Create keep their own copy
// precisely so a caller who keeps using the key it passed in (cpass unlock
// hands the same key on to StartBroker right after opening the Vault with
// it, to name one) is unaffected by the Vault's own Close.
func TestCloseZeroesKeyMaterial(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.cpv")
	callerKey := key(7)
	callerKeyCopy := append([]byte(nil), callerKey...)

	v, err := Create(p, callerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Add("a/one", "value-number-one", AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	v.Close()

	for i, b := range v.key {
		if b != 0 {
			t.Fatalf("v.key[%d] = %#x, want 0 after Close", i, b)
		}
	}
	for i, b := range v.dataKey {
		if b != 0 {
			t.Fatalf("v.dataKey[%d] = %#x, want 0 after Close", i, b)
		}
	}
	if !bytes.Equal(callerKey, callerKeyCopy) {
		t.Fatalf("Close zeroed the caller's own key slice, not just the Vault's copy: got %x, want %x", callerKey, callerKeyCopy)
	}

	// Idempotent: a second Close must not panic or behave differently.
	v.Close()

	// The Vault opened again with the caller's still-intact key must
	// reproduce the same Secret — Close must not have corrupted the file
	// Save already wrote before Close ran.
	v2, err := Open(p, callerKey)
	if err != nil {
		t.Fatalf("re-open after Close: %v", err)
	}
	e, err := v2.Get("a/one")
	if err != nil || e.Value != "value-number-one" {
		t.Fatalf("got %+v, %v", e, err)
	}
}

// TestSaveTightensExistingDirPermissions covers CLA-58: a CPASS_HOME
// directory that already exists (e.g. left at 0755 by a stray umask, or
// simply reused across cpass versions) must be tightened to 0700 on Save,
// not left as-is because MkdirAll is a no-op on it.
func TestSaveTightensExistingDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vaultdir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "v.cpv")
	if _, err := Create(p, key(1)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("vault dir mode = %v, want 0700", st.Mode().Perm())
	}
}

func TestDefaultBindingName(t *testing.T) {
	for in, want := range map[string]string{
		"stripe/live": "STRIPE_LIVE", "a.b-c": "A_B_C", "1x": "_1X", "github/token": "GITHUB_TOKEN",
	} {
		if got := DefaultBindingName(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestValidateHandle(t *testing.T) {
	for _, ok := range []string{"a", "stripe/live", "a/b/c", "x.y_z-1"} {
		if err := ValidateHandle(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/a", "a/", "A", "a b", "a//b", "-a"} {
		if err := ValidateHandle(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestRenameKeepsCustomBinding(t *testing.T) {
	v := &Vault{entries: map[string]*Entry{}, key: key(1), dataKey: key(3)}
	if _, err := v.Add("a/one", "value-number-one", AddOptions{Binding: Binding{Name: "CUSTOM"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Add("a/two", "value-number-two", AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := v.Rename("a/one", "b/one"); err != nil {
		t.Fatal(err)
	}
	if err := v.Rename("a/two", "b/two"); err != nil {
		t.Fatal(err)
	}
	one, _ := v.Get("b/one")
	two, _ := v.Get("b/two")
	if one.Binding.Name != "CUSTOM" || two.Binding.Name != "B_TWO" {
		t.Fatalf("bindings after rename: %s %s", one.Binding.Name, two.Binding.Name)
	}
}
