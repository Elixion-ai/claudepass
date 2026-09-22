//go:build !windows

package broker

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// shortSocketDir returns a fresh directory short enough that a socket file
// inside it stays under sockaddr_un's length limit regardless of how long
// the OS temp dir (t.TempDir()'s base) happens to be on this host.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join("/tmp", fmt.Sprintf("cpass-broker-test-%d", os.Getpid()))
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) }) // best-effort cleanup
	return d
}

// TestEnsureSocketDirTightensExistingDirPermissions covers CLA-58: the
// Broker socket's parent directory (XDG_RUNTIME_DIR or CPASS_HOME) must end
// up 0700 even when it already existed at a looser mode — MkdirAll alone is
// a no-op on an existing directory regardless of its current mode, and the
// "any process running as the same user" trust boundary docs/SECURITY.md
// documents for this socket depends on the directory actually being
// user-only.
func TestEnsureSocketDirTightensExistingDirPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureSocketDir(dir); err != nil {
		t.Fatalf("ensureSocketDir: %v", err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir mode = %v, want 0700", st.Mode().Perm())
	}
}

// TestEnsureSocketDirCreatesMissingDir covers the ordinary first-run case
// alongside the reused-directory one above.
func TestEnsureSocketDirCreatesMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does", "not", "exist", "yet")
	if err := ensureSocketDir(dir); err != nil {
		t.Fatalf("ensureSocketDir: %v", err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir mode = %v, want 0700", st.Mode().Perm())
	}
}

// TestBindSocketPrivatelyIgnoresLooseProcessUmask covers the bind-then-
// chmod window itself: called under the loosest common process umask
// (022, world-readable), bindSocketPrivately's socket file must never be
// group/world-accessible even for the instant between bind(2) and Serve's
// own explicit os.Chmod right after it returns — that's the window a
// permissive inherited umask would otherwise leave open.
func TestBindSocketPrivatelyIgnoresLooseProcessUmask(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "probe.sock")

	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	l, err := bindSocketPrivately(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("socket file mode %v is group/world-accessible right after bindSocketPrivately, under a 0022 process umask", st.Mode().Perm())
	}
}
