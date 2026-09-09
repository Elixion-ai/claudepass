package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDotenv(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestImportThreeEntriesShredsFile(t *testing.T) {
	ve := newVault(t)
	repo := t.TempDir()
	writeDotenv(t, repo, ".env", ""+
		"STRIPE_KEY=sk_live_abcdefghijkl\n"+
		"export DB_URL=postgres://user:pw@host/db\n"+
		"GITHUB_TOKEN=\"ghp_abcdefghijklmnop\"\n")

	r := ve.runIn(repo, nil, "import", ".env")
	if r.code != 0 || !strings.Contains(r.stdout, "imported 3 handle(s)") {
		t.Fatalf("import: %s", r)
	}
	if _, err := os.Stat(filepath.Join(repo, ".env")); !os.IsNotExist(err) {
		t.Fatalf(".env should be gone, err=%v", err)
	}

	ls := ve.run(nil, "ls")
	for _, want := range []string{"stripe_key", "db_url", "github_token"} {
		if !strings.Contains(ls.stdout, want) {
			t.Fatalf("ls missing %s: %s", want, ls)
		}
	}

	raw, err := os.ReadFile(filepath.Join(repo, ".claudepass.toml"))
	if err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
	manifest := string(raw)
	for _, want := range []string{"stripe_key", "db_url", "github_token"} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("manifest missing %s: %s", want, manifest)
		}
	}
	for _, forbidden := range []string{"sk_live_abcdefghijkl", "postgres://user:pw@host/db", "ghp_abcdefghijklmnop"} {
		if strings.Contains(manifest, forbidden) {
			t.Fatalf("manifest contains a value: %s", manifest)
		}
	}

	// The original variable names became the Bindings.
	llong := ve.run(nil, "ls", "-l")
	for _, want := range []string{"STRIPE_KEY", "DB_URL", "GITHUB_TOKEN"} {
		if !strings.Contains(llong.stdout, want) {
			t.Fatalf("binding %s not preserved: %s", want, llong)
		}
	}
}

func TestImportKeepLeavesFile(t *testing.T) {
	ve := newVault(t)
	repo := t.TempDir()
	writeDotenv(t, repo, ".env", "ONE_TOKEN=value-number-one\n")
	r := ve.runIn(repo, nil, "import", ".env", "--keep")
	if r.code != 0 {
		t.Fatalf("import --keep: %s", r)
	}
	raw, err := os.ReadFile(filepath.Join(repo, ".env"))
	if err != nil {
		t.Fatalf("--keep should leave the file: %v", err)
	}
	if !strings.Contains(string(raw), "ONE_TOKEN=value-number-one") {
		t.Fatalf("kept file content changed: %s", raw)
	}
}

func TestImportPrefix(t *testing.T) {
	ve := newVault(t)
	repo := t.TempDir()
	writeDotenv(t, repo, ".env", "API_TOKEN=value-number-one\n")
	r := ve.runIn(repo, nil, "import", ".env", "--prefix", "myapp/")
	if r.code != 0 {
		t.Fatalf("import --prefix: %s", r)
	}
	ls := ve.run(nil, "ls")
	if strings.TrimSpace(ls.stdout) != "myapp/api_token" {
		t.Fatalf("ls after prefixed import: %s", ls)
	}
}

func TestImportExtendsExistingManifest(t *testing.T) {
	ve := newVault(t)
	ve.add("existing/one", "value-number-one")
	repo := t.TempDir()
	ve.runIn(repo, nil, "manifest", "init")
	ve.runIn(repo, nil, "manifest", "add", "existing/one")
	writeDotenv(t, repo, ".env", "NEW_TOKEN=value-number-two\n")
	r := ve.runIn(repo, nil, "import", ".env")
	if r.code != 0 {
		t.Fatalf("import: %s", r)
	}
	check := ve.runIn(repo, nil, "manifest", "check")
	if check.code != 0 || !strings.Contains(check.stdout, "all 2 handles") {
		t.Fatalf("manifest check after extend: %s", check)
	}
}

func TestImportRejectsCollidingHandle(t *testing.T) {
	ve := newVault(t)
	ve.add("api_token", "already-here-value")
	repo := t.TempDir()
	writeDotenv(t, repo, ".env", "API_TOKEN=some-other-value\n")
	r := ve.runIn(repo, nil, "import", ".env")
	if r.code == 0 || !strings.Contains(r.stderr, "api_token") {
		t.Fatalf("want collision refusal: %s", r)
	}
	// Refused before any destructive action: the file must survive.
	if _, err := os.Stat(filepath.Join(repo, ".env")); err != nil {
		t.Fatalf(".env should survive a refused import: %v", err)
	}
	// And the pre-existing handle must be untouched.
	if _, err := os.Stat(filepath.Join(repo, ".claudepass.toml")); err == nil {
		t.Fatalf("manifest should not be created on a refused import")
	}
}

func TestImportShortValueRefusedBeforeShredding(t *testing.T) {
	ve := newVault(t)
	repo := t.TempDir()
	writeDotenv(t, repo, ".env", "SHORT=abc\n")
	r := ve.runIn(repo, nil, "import", ".env")
	if r.code == 0 || !strings.Contains(r.stderr, "shorter than 8") {
		t.Fatalf("want short-value refusal: %s", r)
	}
	if _, err := os.Stat(filepath.Join(repo, ".env")); err != nil {
		t.Fatalf(".env should survive a refused import: %v", err)
	}
}

func TestImportMalformedDotenv(t *testing.T) {
	ve := newVault(t)
	repo := t.TempDir()
	writeDotenv(t, repo, ".env", "NOT_VALID_LINE\n")
	r := ve.runIn(repo, nil, "import", ".env")
	if r.code == 0 {
		t.Fatalf("want failure on malformed dotenv: %s", r)
	}
}
