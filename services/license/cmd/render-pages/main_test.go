package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenderWritesEveryFixtureNonEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := Render(dir); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"license-ready.html",
		"license-already-shown.html",
		"license-pending.html",
		"license-invalid.html",
		"checkout-error.html",
		"reissue-sent.html",
		"reissue-not-found.html",
		"reissue-inactive.html",
		"reissue-missing-email.html",
		"reissue-mail-failed.html",
		"internal-error.html",
		"email-plain.txt",
		"email-html.html",
	}
	for _, name := range want {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("expected fixture %s: %v", name, err)
		}
		if fi.Size() == 0 {
			t.Fatalf("fixture %s is empty", name)
		}
	}
}

func TestRunRequiresOut(t *testing.T) {
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devnull.Close() }() // best-effort cleanup
	if code := run(nil, devnull); code != 2 {
		t.Fatalf("run with no -out: code = %d, want 2", code)
	}
}
