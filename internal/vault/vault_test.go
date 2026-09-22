package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
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

// TestSaveDurablyReplacesTheFileWithNoTempDebris is CLA-56's regression
// test. A Go test cannot observe fsync's actual effect — that only shows up
// across a real crash — so this instead pins down the integration point
// that CLA-56 changed: Vault.Save must go through internal/atomicfile's
// write-fsync-rename-fsync sequence (already unit-tested for the fsync
// calls themselves in internal/atomicfile) rather than a bare os.WriteFile,
// for every one of several successive Saves — no unique per-invocation temp
// file (CLA-55's own requirement) is ever left behind if that sequence
// completed for both v.cpv and its CLA-59 backup v.cpv.bak, so a leftover
// "*.tmp-*" after several Saves would mean the durable-write path was
// bypassed or aborted partway through.
func TestSaveDurablyReplacesTheFileWithNoTempDebris(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "v.cpv")
	v, err := Create(p, key(6))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := v.Add(fmt.Sprintf("h/%d", i), fmt.Sprintf("value-number-%d-ok", i), AddOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := v.Save(); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// v.cpv and its CLA-59 backup v.cpv.bak are the only two files any
	// number of successive Saves should leave behind — never a leftover
	// "v.cpv.tmp-*" staging file from an aborted or bypassed atomicfile
	// sequence.
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != "v.cpv" || names[1] != "v.cpv.bak" {
		t.Fatalf("directory should hold only v.cpv and v.cpv.bak after 3 Saves, got %v", names)
	}
	if _, err := Open(p, key(6)); err != nil {
		t.Fatalf("vault does not reopen after repeated Save: %v", err)
	}
}

// TestSaveKeepsThePreviousGenerationAsBak is CLA-59's regression test.
// Create itself Saves once (the first generation, empty, with nothing yet
// to back up); after a second Save, vault.cpv.bak must exist and decrypt on
// its own, holding that first generation — the acceptance criterion in so
// many words. A third Save then demonstrates the fuller claim
// docs/SECURITY.md makes: a Handle removed by one Save still exists,
// encrypted, in .bak until the *next* write, because .bak always trails the
// live file by exactly one generation.
func TestSaveKeepsThePreviousGenerationAsBak(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.cpv")
	k := key(4)
	v, err := Create(p, k) // Save #1: the first generation, empty.
	if err != nil {
		t.Fatal(err)
	}
	bak := p + ".bak"
	if _, err := os.Stat(bak); err == nil {
		t.Fatal("a brand-new vault has no prior generation to back up yet")
	}

	if _, err := v.Add("first/handle", "first-generation-value", AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil { // Save #2: backs up Save #1's (empty) generation.
		t.Fatal(err)
	}
	empty, err := Open(bak, k)
	if err != nil {
		t.Fatalf("vault.cpv.bak does not decrypt after two Saves: %v", err)
	}
	if empty.Count() != 0 {
		t.Fatalf(".bak after two Saves should hold the empty first generation, got %d entries", empty.Count())
	}

	if err := v.Remove("first/handle"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Add("second/handle", "second-generation-value", AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil { // Save #3: backs up Save #2's generation.
		t.Fatal(err)
	}

	// The live file reflects Save #3.
	live, err := Open(p, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := live.Get("first/handle"); err == nil {
		t.Fatal("first/handle should be gone from the live vault")
	}
	if _, err := live.Get("second/handle"); err != nil {
		t.Fatalf("second/handle missing from the live vault: %v", err)
	}

	// .bak now reflects Save #2's generation: still holding the
	// since-removed first/handle, predating second/handle entirely.
	prior, err := Open(bak, k)
	if err != nil {
		t.Fatalf("vault.cpv.bak does not decrypt: %v", err)
	}
	e, err := prior.Get("first/handle")
	if err != nil || e.Value != "first-generation-value" {
		t.Fatalf(".bak should still hold the removed Handle: %+v, %v", e, err)
	}
	if _, err := prior.Get("second/handle"); err == nil {
		t.Fatal(".bak should predate second/handle")
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

// TestConcurrentAddsAllSurvive is CLA-55's regression test: N concurrent
// writers each doing their own Open -> mutate -> Save cycle against the
// same Vault file must not lose any of the N additions, and must not race
// each other's Save (a shared, fixed tmp filename made that a second
// failure mode on top of the lost update). Run under -race.
func TestConcurrentAddsAllSurvive(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.cpv")
	k := key(9)
	if _, err := Create(p, k); err != nil {
		t.Fatal(err)
	}
	const n = 30
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handle := fmt.Sprintf("concurrent/h%02d", i)
			_, err := Update(p, k, func(v *Vault) error {
				_, err := v.Add(handle, fmt.Sprintf("value-number-%02d-long-enough", i), AddOptions{})
				return err
			})
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("update %d: %v", i, err)
		}
	}
	v, err := Open(p, k)
	if err != nil {
		t.Fatal(err)
	}
	if v.Count() != n {
		t.Fatalf("vault has %d entries, want %d — a concurrent Save silently lost one", v.Count(), n)
	}
	for i := 0; i < n; i++ {
		h := fmt.Sprintf("concurrent/h%02d", i)
		if _, err := v.Get(h); err != nil {
			t.Errorf("missing %s: %v", h, err)
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
