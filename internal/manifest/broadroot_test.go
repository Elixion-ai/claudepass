package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBroadRootDetectsFilesystemRootAndHome(t *testing.T) {
	if broad, err := BroadRoot(string(filepath.Separator)); err != nil || !broad {
		t.Fatalf("the filesystem root must be broad: %v %v", broad, err)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	if broad, err := BroadRoot(home); err != nil || !broad {
		t.Fatalf("the caller's home directory must be broad: %v %v", broad, err)
	}

	ordinary := mkdir(t, home, "projects", "my-repo")
	if broad, err := BroadRoot(ordinary); err != nil || broad {
		t.Fatalf("an ordinary project directory under home must not be broad: %v %v", broad, err)
	}
}

// TestShouldWarnBroadRootTightensExistingDirPermissions is CLA-98 item 7's
// regression test for the shouldWarnBroadRoot call site: the
// broadroot-warned marker directory, when it already exists at 0755 (a
// stray umask, or left behind from before this hardening), must be
// tightened to 0700 by the ensurePrivateDir call inside
// shouldWarnBroadRoot, the same as the other two call sites in global.go.
func TestShouldWarnBroadRootTightensExistingDirPermissions(t *testing.T) {
	cpassHome := t.TempDir()
	t.Setenv("CPASS_HOME", cpassHome)
	markerDir := filepath.Join(cpassHome, broadRootWarnedDirName)
	if err := os.Mkdir(markerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	shouldWarnBroadRoot("/some/broad/root")
	fi, err := os.Stat(markerDir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("broadroot-warned dir mode = %v, want 0700", fi.Mode().Perm())
	}
}
