//go:build !windows

package lockfile

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// Lock is a held exclusive lock: an open fd holding flock(2)'s LOCK_EX.
type Lock struct {
	f *os.File
}

// Acquire opens (creating if needed) the lock file at path and blocks,
// retrying every pollInterval, until it holds an exclusive flock or timeout
// elapses. path's directory must already exist.
func Acquire(path string, timeout time.Duration) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lockfile: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &Lock{f: f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("lockfile: %w", err)
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("%w: %s", ErrTimeout, path)
		}
		time.Sleep(pollInterval)
	}
}

// Release unlocks and closes the lock file. The lock file itself is left in
// place — flock needs nothing removed, and deleting it here would only
// reopen the "two processes, two different inodes, no actual mutual
// exclusion" race this package exists to close.
func (l *Lock) Release() error {
	defer func() { _ = l.f.Close() }()
	return syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
}
