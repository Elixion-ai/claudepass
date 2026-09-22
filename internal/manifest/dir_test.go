package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEnsurePrivateDirTightensAnExistingLooserDir is CLA-98 item 7's
// regression test for the shared helper itself: os.MkdirAll is a no-op on
// a directory that already exists, regardless of its current mode, so a
// directory left loose by a stray umask or a reused $CPASS_HOME would
// otherwise stay loose forever without ensurePrivateDir's explicit chmod
// after it.
func TestEnsurePrivateDirTightensAnExistingLooserDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v, want 0700", fi.Mode().Perm())
	}
}

// TestEnsurePrivateDirCreatesAMissingDirAt0700 covers the other branch:
// a directory that does not exist yet (and whose parents don't either) is
// created at 0700 directly.
func TestEnsurePrivateDirCreatesAMissingDirAt0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not", "created", "yet")
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v, want 0700", fi.Mode().Perm())
	}
}
