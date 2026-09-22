package manifest

import (
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
