// Package lockfile provides a simple, blocking exclusive lock on a sidecar
// file, used to serialize the whole read-modify-write cycle around one of
// ClaudePass's on-disk stores (the Vault, the Global Manifest) across
// concurrent `cpass` processes. Without it, two processes that each open,
// mutate in memory, and save race the save: the second one's write is a
// full snapshot of its own (now stale) in-memory state, so it silently
// overwrites whatever the first one added (CLA-55, CLA-93).
//
// A reader never needs this lock: every store here is saved by an atomic
// rename (see internal/atomicfile), so a concurrent reader always sees
// either the pre-write or the post-write file in full, never a partial one.
// Only a writer's Open -> mutate -> Save cycle needs to be serialized.
//
// Backed by flock(2) (lockfile_unix.go). ADR-0007 scopes cpass to macOS and
// Linux; the Windows build (lockfile_windows.go) is a no-op rather than a
// new failure mode on a platform that was never race-free to begin with.
package lockfile

import (
	"errors"
	"time"
)

// pollInterval is how often Acquire retries a contended lock.
const pollInterval = 20 * time.Millisecond

// DefaultTimeout is how long Acquire waits for a contended lock before
// giving up with ErrTimeout. Generous enough to queue behind another
// writer's ordinary Open-mutate-Save cycle (millisecond-scale), small
// enough that a genuinely wedged neighbour is reported rather than hung on
// forever — flock itself is released by the kernel the instant the holding
// process exits or closes the fd, so there is no "stale lock file" case to
// recover from by hand.
const DefaultTimeout = 5 * time.Second

// ErrTimeout is returned when a lock could not be acquired within the
// timeout: another cpass process is holding it for longer than expected.
var ErrTimeout = errors.New("lockfile: timed out waiting for the lock")

// Lock is a held exclusive lock on one sidecar file, returned by Acquire.
// Release it exactly once; a Lock is not safe to share between goroutines.
//
// Acquire and the Release method are implemented per platform
// (lockfile_unix.go, lockfile_windows.go); this file holds only what every
// platform shares.
