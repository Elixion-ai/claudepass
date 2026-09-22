package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
	// v.cpv, its CLA-59 backup v.cpv.bak, and Create's own CLA-98
	// v.cpv.lock sidecar (never removed, per lockfile.Release's own doc
	// comment) are the only files any number of successive Saves should
	// leave behind — never a leftover "v.cpv.tmp-*" staging file from an
	// aborted or bypassed atomicfile sequence.
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	sort.Strings(names)
	want := []string{"v.cpv", "v.cpv.bak", "v.cpv.lock"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("directory should hold only %v after Create and 3 Saves, got %v", want, names)
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

// TestUpdateZeroesTheVaultItOpened covers CLA-60 for every write command at
// once: CLI and MCP writers all go through Update (CLA-55), which owns the
// Vault it opens and must zero its key material before returning, whether
// fn succeeds or fails.
func TestUpdateZeroesTheVaultItOpened(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.cpv")
	k := key(8)
	if _, err := Create(p, k); err != nil {
		t.Fatal(err)
	}
	for _, fail := range []bool{false, true} {
		var seen *Vault
		err := Update(p, k, func(v *Vault) error {
			seen = v
			if fail {
				return errors.New("mutation refused")
			}
			_, err := v.Add("u/handle", "update-value-long-enough", AddOptions{})
			return err
		})
		if fail != (err != nil) {
			t.Fatalf("fail=%v: Update returned %v", fail, err)
		}
		if !bytes.Equal(seen.key, make([]byte, len(seen.key))) || !bytes.Equal(seen.dataKey, make([]byte, len(seen.dataKey))) {
			t.Fatalf("fail=%v: Update returned without zeroing the Vault's key material", fail)
		}
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

// TestRewrapChangesUnlockKeyKeepsData covers CLA-97's vault primitive:
// Rewrap must swap which key opens the Vault without touching a single
// Entry, and must zero the old key it replaces (CLA-60) rather than leaving
// it sitting in memory once superseded.
func TestRewrapChangesUnlockKeyKeepsData(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.cpv")
	oldKey := key(1)
	newKey := key(2)

	v, err := Create(p, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Add("a/one", "value-number-one", AddOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	// v's own copy of the pre-Rewrap key (not oldKey, the caller's slice —
	// Create keeps its own copy, same as Open) is the one Rewrap must zero
	// in place; capture its backing array, not a copy of its bytes, so the
	// check below observes Rewrap's actual mutation.
	preRewrap := v.key
	if err := v.Rewrap(newKey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v.key, newKey) {
		t.Fatalf("v.key after Rewrap = %x, want the new key %x", v.key, newKey)
	}
	for i, b := range preRewrap {
		if b != 0 {
			t.Fatalf("preRewrap[%d] = %#x, want 0: Rewrap must zero the key it replaces (CLA-60)", i, b)
		}
	}
	if err := v.Save(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(p, oldKey); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("Open with the pre-Rewrap key after Save = %v, want ErrWrongKey", err)
	}
	v2, err := Open(p, newKey)
	if err != nil {
		t.Fatalf("Open with the post-Rewrap key: %v", err)
	}
	e, err := v2.Get("a/one")
	if err != nil || e.Value != "value-number-one" {
		t.Fatalf("Rewrap must not touch Entries: got %+v, %v", e, err)
	}
}

// TestRewrapRefusesWrongSizedKey mirrors Create/Open's own key-size check:
// Rewrap must never silently accept a key that could not itself unlock
// anything.
func TestRewrapRefusesWrongSizedKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.cpv")
	v, err := Create(p, key(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Rewrap([]byte("too-short")); err == nil {
		t.Fatal("Rewrap accepted a wrong-sized key")
	}
	if !bytes.Equal(v.key, key(1)) {
		t.Fatal("a refused Rewrap must leave the existing key untouched")
	}
}

// TestUpdateRewrapIsHowABrokerUpgradeActuallyRuns exercises Rewrap the way
// CLA-97's passphrase-KDF upgrade calls it: inside Update, under its lock,
// so the re-wrap and the Save that makes it durable happen as one atomic
// Open -> mutate -> Save cycle (CLA-55) rather than two separate steps a
// concurrent writer could interleave with.
func TestUpdateRewrapIsHowABrokerUpgradeActuallyRuns(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.cpv")
	oldKey := key(3)
	newKey := key(4)
	if _, err := Create(p, oldKey); err != nil {
		t.Fatal(err)
	}

	if err := Update(p, oldKey, func(v *Vault) error {
		return v.Rewrap(newKey)
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(p, oldKey); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("Open with the pre-upgrade key = %v, want ErrWrongKey", err)
	}
	v, err := Open(p, newKey)
	if err != nil {
		t.Fatalf("Open with the upgraded key: %v", err)
	}
	v.Close()
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
			err := Update(p, k, func(v *Vault) error {
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

// TestConcurrentCreateOnlyOneWins is CLA-98 item 1's regression test: two
// concurrent `cpass init` runs against a fresh path must not both create
// the Vault. Before the fix, Create's Exists check ran unlocked, so both
// goroutines could pass it and each call Save with its own key — the
// second Save silently overwriting the first's data key. With the fix,
// exactly one Create succeeds and every other sees ErrExists (or the
// "already exists" error Create wraps it in); whichever key won is the one
// that unlocks the file afterwards.
func TestConcurrentCreateOnlyOneWins(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.cpv")
	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var winner byte
	oks := 0
	errsSeen := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := key(byte(i + 1))
			v, err := Create(p, k)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				oks++
				winner = byte(i + 1)
				v.Close()
			} else {
				errsSeen++
				if !strings.Contains(err.Error(), "already exists") {
					t.Errorf("goroutine %d: unexpected error: %v", i, err)
				}
			}
		}(i)
	}
	wg.Wait()
	if oks != 1 {
		t.Fatalf("got %d successful Creates, want exactly 1 (%d refused)", oks, errsSeen)
	}
	v, err := Open(p, key(winner))
	if err != nil {
		t.Fatalf("Open with the winning Create's key: %v", err)
	}
	v.Close()
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
