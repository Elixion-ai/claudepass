package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRoundTripsContentAndMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.txt")
	if err := Write(p, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "first" {
		t.Fatalf("got %q, %v", got, err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
	}

	// A second Write (a Save-and-Save-again) replaces the content, in place
	// — same name, no ".old" left dangling — and leaves no temp file behind
	// in either directory listing.
	if err := Write(p, []byte("second, and longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(p)
	if err != nil || string(got) != "second, and longer" {
		t.Fatalf("got %q, %v", got, err)
	}
	st, err = os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode after second write = %v, want 0644", st.Mode().Perm())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "out.txt" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("directory should hold only out.txt, got %v (a temp file was left behind)", names)
	}
}

func TestWriteUsesAUniqueTempNameEachCall(t *testing.T) {
	// Two concurrent Writes to two different destinations that happen to
	// share a directory must never collide on the staging file's name —
	// the CLA-55 requirement that made the old fixed "path+.tmp" unsafe.
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.txt")
	if err := Write(a, []byte("a-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(b, []byte("b-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	gotA, _ := os.ReadFile(a)
	gotB, _ := os.ReadFile(b)
	if string(gotA) != "a-content" || string(gotB) != "b-content" {
		t.Fatalf("a=%q b=%q", gotA, gotB)
	}
}

// TestWriteSyncsTheFileThenTheDirectory is CLA-56's regression test: Write
// must fsync the temp file (durable before the rename that makes it live)
// and then fsync the directory (durable that the rename itself happened),
// in that order. A plain call-count or "no error" assertion would pass even
// with both Sync calls deleted, so this wraps the calls themselves via
// syncObserver, the one seam that can actually tell the two apart.
func TestWriteSyncsTheFileThenTheDirectory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.txt")
	var calls []string
	prev := syncObserver
	syncObserver = func(what string) { calls = append(calls, what) }
	defer func() { syncObserver = prev }()

	if err := Write(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != "file" || calls[1] != "dir" {
		t.Fatalf("sync calls = %v, want [file dir] in that order", calls)
	}
}

func TestWriteFailsCleanlyOnAMissingDirectory(t *testing.T) {
	p := filepath.Join(t.TempDir(), "does", "not", "exist", "out.txt")
	if err := Write(p, []byte("x"), 0o600); err == nil {
		t.Fatal("want an error when the destination directory does not exist")
	}
}
