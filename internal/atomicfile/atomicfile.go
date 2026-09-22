// Package atomicfile writes a file so a reader — including a crash and
// restart, not just a concurrent process — only ever sees the old content in
// full or the new content in full, never a partial write. Write stages the
// new content in a per-call unique temporary file in the same directory (so
// two writers, even two Save calls racing in the same process, can never
// collide on a shared name — CLA-55), fsyncs it before renaming it over the
// destination (POSIX rename is atomic with respect to a concurrent reader),
// and fsyncs the directory afterwards so the rename itself survives a crash
// or power loss, not just the bytes it points at (CLA-56).
//
// This alone does not make two concurrent writers safe: it guarantees a
// single Write lands whole or not at all, not that two overlapping
// Open -> mutate -> Write cycles agree on the result. See
// internal/lockfile for that.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write atomically replaces path with data, mode perm. path's directory
// must already exist.
func Write(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	name := tmp.Name()
	defer func() {
		// Reached only when a step below failed before the rename landed:
		// once the file is renamed into place there is nothing left at name
		// to clean up, and a redundant Remove's own error would only mask
		// the real one.
		if err != nil {
			_ = os.Remove(name)
		}
	}()
	if _, werr := tmp.Write(data); werr != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: %w", werr)
	}
	if serr := tmp.Sync(); serr != nil {
		_ = tmp.Close()
		return fmt.Errorf("atomicfile: %w", serr)
	}
	notifySync("file")
	if cerr := tmp.Close(); cerr != nil {
		return fmt.Errorf("atomicfile: %w", cerr)
	}
	// os.CreateTemp always creates at 0600; chmod to the mode the caller
	// actually asked for (e.g. a Manifest's 0644) before it becomes visible
	// at its final name.
	if cherr := os.Chmod(name, perm); cherr != nil {
		return fmt.Errorf("atomicfile: %w", cherr)
	}
	if rerr := os.Rename(name, path); rerr != nil {
		return fmt.Errorf("atomicfile: %w", rerr)
	}
	return syncDir(dir)
}

// syncDir fsyncs dir, making a rename into it durable. A directory fsync is
// meaningless before the rename it is meant to cover, so this is only ever
// called after Rename above succeeds.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("atomicfile: %w", err)
	}
	notifySync("dir")
	return nil
}

// syncObserver, when non-nil, is called once for each fsync Write performs
// (the temp file's, then — after the rename — the directory's), in that
// order. It exists only for this package's own tests (CLA-56): Go has no
// portable way to observe fsync's actual effect, durability across a crash,
// any other way, so the regression test for "Save calls Sync" wraps the
// call itself instead.
var syncObserver func(what string)

func notifySync(what string) {
	if syncObserver != nil {
		syncObserver(what)
	}
}
