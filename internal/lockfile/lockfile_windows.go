//go:build windows

package lockfile

import "time"

// Lock is a no-op placeholder on Windows; see the package doc comment.
type Lock struct{}

// Acquire always succeeds immediately on Windows: ADR-0007 scopes cpass to
// macOS and Linux, and a Windows build should keep its pre-existing
// (unlocked) behaviour rather than gain a new way for every write command
// to fail on a platform this package was never asked to make race-free.
func Acquire(path string, timeout time.Duration) (*Lock, error) {
	return &Lock{}, nil
}

// Release is a no-op on Windows.
func (l *Lock) Release() error { return nil }
