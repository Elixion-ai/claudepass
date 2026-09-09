package vault

import (
	"bytes"
	"errors"
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
	v.Add("a/one", "value-number-one", AddOptions{Binding: Binding{Name: "CUSTOM"}})
	v.Add("a/two", "value-number-two", AddOptions{})
	v.Rename("a/one", "b/one")
	v.Rename("a/two", "b/two")
	one, _ := v.Get("b/one")
	two, _ := v.Get("b/two")
	if one.Binding.Name != "CUSTOM" || two.Binding.Name != "B_TWO" {
		t.Fatalf("bindings after rename: %s %s", one.Binding.Name, two.Binding.Name)
	}
}
