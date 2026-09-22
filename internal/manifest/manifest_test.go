package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

func TestRoundTripAndFind(t *testing.T) {
	root := t.TempDir()
	m := &Manifest{Path: filepath.Join(root, FileName)}
	m.Add(Entry{Handle: "stripe/live", Binding: vault.Binding{Name: "STRIPE_SECRET_KEY"}})
	m.Add(Entry{Handle: "gcp/sa", Binding: vault.Binding{Kind: vault.BindFile, Name: "GOOGLE_APPLICATION_CREDENTIALS"}})
	m.Add(Entry{Handle: "github/token"})
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(m.Path)
	if !strings.Contains(string(raw), `"gcp/sa" = { binding = "GOOGLE_APPLICATION_CREDENTIALS", kind = "file" }`) {
		t.Fatalf("file:\n%s", raw)
	}
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := Find(sub)
	if err != nil || p != m.Path {
		t.Fatalf("find: %s %v", p, err)
	}
	m2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(m2.Entries) != 3 || m2.Entries[0].Handle != "gcp/sa" || m2.Entries[0].Binding.Kind != vault.BindFile {
		t.Fatalf("entries: %+v", m2.Entries)
	}
	if m2.Entries[1].Binding.Name != "GITHUB_TOKEN" || m2.Entries[2].Binding.Name != "STRIPE_SECRET_KEY" {
		t.Fatalf("bindings: %+v", m2.Entries)
	}
	if _, err := Find(t.TempDir()); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestLoadRejectsBadHandleAndKind(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(p, []byte("[secrets]\n\"Bad Handle\" = \"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("want error for bad handle")
	}
	if err := os.WriteFile(p, []byte("[secrets]\n\"a/b\" = { kind = \"blob\" }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("want kind error, got %v", err)
	}
}

// TestUnparsedLinesSurviveASave is the regression test for the round-trip
// hole the [options] opt-out would otherwise fall into: Save regenerates the
// whole file from parsed struct fields, so anything Load did not understand
// used to vanish the next time any command touched the Manifest. A project
// that committed `global = false` would silently start receiving Global
// Handles again after an unrelated `cpass manifest add`.
func TestUnparsedLinesSurviveASave(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	original := `[options]
global = false
future_option = "x"

[secrets]
"stripe/live" = ""

[future_section]
key = 1
`
	if err := os.WriteFile(p, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !m.GlobalDisabled {
		t.Fatal("global = false must set GlobalDisabled")
	}
	// An unrelated edit, the way `cpass manifest add` makes one.
	m.Add(Entry{Handle: "db/url"})
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	for _, want := range []string{"global = false", `future_option = "x"`, "[future_section]", "key = 1", `"db/url"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("%q did not survive the save:\n%s", want, raw)
		}
	}
	again, err := Load(p)
	if err != nil || !again.GlobalDisabled || !again.Has("db/url") || !again.Has("stripe/live") {
		t.Fatalf("reload: %+v %v", again, err)
	}
}

// TestGlobalDisabledOffWritesNoOptionsSection keeps the common case clean: a
// project that has never opted out carries no [options] block at all, so the
// feature costs nothing in the diff of an ordinary Manifest.
func TestGlobalDisabledOffWritesNoOptionsSection(t *testing.T) {
	p := filepath.Join(t.TempDir(), FileName)
	m := &Manifest{Path: p}
	m.Add(Entry{Handle: "stripe/live"})
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "[options]") {
		t.Fatalf("unexpected options section:\n%s", raw)
	}
	// And turning the opt-out on and off again leaves no residue.
	m.GlobalDisabled = true
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(p)
	if err != nil || !reloaded.GlobalDisabled {
		t.Fatalf("reload: %+v %v", reloaded, err)
	}
	reloaded.GlobalDisabled = false
	if err := reloaded.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(p)
	if strings.Contains(string(raw), "global = false") || strings.Contains(string(raw), "[options]") {
		t.Fatalf("opt-out left residue after being turned off:\n%s", raw)
	}
}

// TestLoadIgnoresAnUnrecognisedGlobalValue: only the exact literal `false`
// disables Global Handles. Anything else is kept verbatim rather than guessed
// at, so a typo fails safe (Handles keep flowing) and visibly (the line stays
// in the file for a human to see).
func TestLoadIgnoresAnUnrecognisedGlobalValue(t *testing.T) {
	for _, line := range []string{"global = true", "global = \"false\"", "global = 0", "globally = false"} {
		p := filepath.Join(t.TempDir(), FileName)
		if err := os.WriteFile(p, []byte("[options]\n"+line+"\n[secrets]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		m, err := Load(p)
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if m.GlobalDisabled {
			t.Fatalf("%q must not disable Global Handles", line)
		}
		if err := m.Save(); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(p)
		if !strings.Contains(string(raw), line) {
			t.Fatalf("%q was dropped on save:\n%s", line, raw)
		}
	}
}
