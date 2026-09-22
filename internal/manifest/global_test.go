package manifest

import (
	"os"
	"path/filepath"
	"strings"
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
