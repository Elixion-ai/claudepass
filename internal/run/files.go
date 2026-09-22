package run

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Elixion-ai/claudepass/internal/broker"
)

// runRoot is where file Bindings are materialised: $CPASS_HOME/run/<id>/.
func runRoot() (string, error) {
	home, err := broker.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "run"), nil
}

// runDir holds the files for one invocation.
type runDir struct {
	path  string
	files []string
}

// newRunDir creates a private per-invocation directory and records this
// process's pid so a stale directory (cpass itself killed) can be swept.
func newRunDir() (*runDir, error) {
	root, err := runRoot()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	sweepStale(root)
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, hex.EncodeToString(id[:]))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ".pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return nil, err
	}
	return &runDir{path: dir}, nil
}

// add writes a Secret to a 0600 file and returns its path.
func (d *runDir) add(handle, value string) (string, error) {
	name := strings.ReplaceAll(handle, "/", "-")
	p := filepath.Join(d.path, name)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, werr := f.WriteString(value)
	cerr := f.Close()
	if werr != nil {
		return "", werr
	}
	if cerr != nil {
		return "", cerr
	}
	d.files = append(d.files, p)
	return p, nil
}

// destroy overwrites every file with zeros, unlinks them, and removes the
// directory. Errors are ignored: this runs on every exit path.
func (d *runDir) destroy() {
	if d == nil {
		return
	}
	shredDir(d.path)
}

func shredDir(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Size() > 0 {
			if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
				zeros := make([]byte, st.Size())
				_, _ = f.Write(zeros)
				_ = f.Sync()
				_ = f.Close()
			}
		}
		_ = os.Remove(p)
	}
	_ = os.Remove(dir)
}

// staleRunDirMaxAge bounds how long a run directory may survive even when
// its .pid names a live process, as insurance against PID reuse: if a
// cpass process holding a file-Binding Secret was SIGKILLed and the OS
// later recycles its pid for an unrelated process before the next sweep,
// processAlive(pid) reads true forever and PID liveness alone never
// catches it (docs/THREATS.md). Three times broker.DefaultIdleTimeout — the
// same "how long is an unattended session still plausibly active" duration
// the Broker itself uses before it forgets an unlock key — comfortably
// outlives any ordinary `cpass run` invocation, including a long-running
// dev server or watcher (PRD story #18's no-buffering-delay guarantee
// exists precisely so those stay wrapped for a long time), while still
// eventually reclaiming a directory PID liveness alone would hold onto
// forever. It is a bound, not a guarantee either way: see docs/THREATS.md
// for the disclosed limitation this trades in.
const staleRunDirMaxAge = 3 * broker.DefaultIdleTimeout

// tooOldToTrustPID reports whether dir was created longer ago than
// staleRunDirMaxAge, using its own modification time — set once, when
// newRunDir creates it and writes its .pid and Secret files, and never
// touched again until shredDir removes them — as the bound-of-last-resort
// against PID reuse described above. A Stat failure (already gone, or a
// permissions oddity) is reported as "not too old" so the caller falls
// through to its ordinary PID-liveness handling rather than acting on an
// error here.
func tooOldToTrustPID(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) > staleRunDirMaxAge
}

// sweepStale removes run directories whose owning cpass process is gone,
// or that have simply sat there too long to trust their .pid's liveness
// reading any further regardless (see staleRunDirMaxAge).
func sweepStale(root string) {
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if tooOldToTrustPID(dir) {
			shredDir(dir)
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, ".pid"))
		if err != nil {
			shredDir(dir)
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || pid == os.Getpid() || processAlive(pid) {
			continue
		}
		shredDir(dir)
	}
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
