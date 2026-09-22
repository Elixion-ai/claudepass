package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLoadGlobalOnAMachineWithNoGlobalManifest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CPASS_HOME", home)
	m, err := LoadGlobal()
	if err != nil {
		t.Fatalf("a missing Global Manifest is the ordinary state, not an error: %v", err)
	}
	if len(m.Entries) != 0 || m.Path != filepath.Join(home, GlobalFileName) {
		t.Fatalf("manifest: %+v", m)
	}
	// It is usable straight away: Add then SaveGlobal, with no init step.
	m.Add(Entry{Handle: "openai/key"})
	if err := m.SaveGlobal(); err != nil {
		t.Fatal(err)
	}
	again, err := LoadGlobal()
	if err != nil || !again.Has("openai/key") {
		t.Fatalf("round trip: %+v %v", again, err)
	}
}

func TestSaveGlobalCreatesTheHomeDirectory(t *testing.T) {
	home := filepath.Join(t.TempDir(), "not", "created", "yet")
	t.Setenv("CPASS_HOME", home)
	m, err := LoadGlobal()
	if err != nil {
		t.Fatal(err)
	}
	m.Add(Entry{Handle: "openai/key"})
	if err := m.SaveGlobal(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("ClaudePass home mode = %v, want 0700", fi.Mode().Perm())
	}
}

// TestSaveGlobalTightensExistingDirPermissions is CLA-98 item 7's
// regression test for the SaveGlobal call site: unlike
// TestSaveGlobalCreatesTheHomeDirectory above (a missing home directory),
// this pre-creates CPASS_HOME at 0755 — a stray umask, or a directory that
// already existed for some other reason before `cpass` ever touched it —
// and SaveGlobal must still tighten it to 0700, not leave it as MkdirAll
// alone (a no-op on an existing directory) would.
func TestSaveGlobalTightensExistingDirPermissions(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CPASS_HOME", home)
	m, err := LoadGlobal()
	if err != nil {
		t.Fatal(err)
	}
	m.Add(Entry{Handle: "openai/key"})
	if err := m.SaveGlobal(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("ClaudePass home mode = %v, want 0700", fi.Mode().Perm())
	}
}

// TestUpdateGlobalTightensExistingDirPermissions is item 7's regression
// test for UpdateGlobal's own ensurePrivateDir call, separate from (and
// reached before) SaveGlobal's.
func TestUpdateGlobalTightensExistingDirPermissions(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CPASS_HOME", home)
	if _, err := UpdateGlobal(func(m *Manifest) error {
		m.Add(Entry{Handle: "openai/key"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("ClaudePass home mode = %v, want 0700", fi.Mode().Perm())
	}
}

// TestUpdateGlobalConcurrentDeclarationsAllSurvive is CLA-93's regression
// test: N goroutines each declaring a distinct Handle through UpdateGlobal
// must all survive in global.toml — before the fix, LoadGlobal -> Add ->
// SaveGlobal raced and silently lost several of the N declarations. Run
// under -race.
func TestUpdateGlobalConcurrentDeclarationsAllSurvive(t *testing.T) {
	t.Setenv("CPASS_HOME", t.TempDir())
	const n = 30
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			handle := fmt.Sprintf("concurrent/h%02d", i)
			_, err := UpdateGlobal(func(m *Manifest) error {
				m.Add(Entry{Handle: handle})
				return nil
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
	m, err := LoadGlobal()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != n {
		t.Fatalf("global.toml has %d entries, want %d — a concurrent SaveGlobal silently lost one", len(m.Entries), n)
	}
	for i := 0; i < n; i++ {
		h := fmt.Sprintf("concurrent/h%02d", i)
		if !m.Has(h) {
			t.Errorf("missing %s", h)
		}
	}
}

func TestGlobalManifestSaysWhatItIs(t *testing.T) {
	t.Setenv("CPASS_HOME", t.TempDir())
	m, err := LoadGlobal()
	if err != nil {
		t.Fatal(err)
	}
	m.Add(Entry{Handle: "openai/key"})
	if err := m.SaveGlobal(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	// The header a human opening this file reads must describe the machine,
	// not "this project" — it is the project Manifest's header that says that.
	if !strings.Contains(string(raw), "Global Manifest") || strings.Contains(string(raw), "this project needs") {
		t.Fatalf("global.toml header:\n%s", raw)
	}
	if strings.Contains(string(raw), "openai-key-value") {
		t.Fatalf("a Manifest must never hold a value:\n%s", raw)
	}
}
