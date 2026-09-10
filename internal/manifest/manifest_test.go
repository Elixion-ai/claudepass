package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"claudepass/internal/vault"
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
