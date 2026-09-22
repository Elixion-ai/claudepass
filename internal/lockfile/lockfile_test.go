package lockfile

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAcquireExcludesAConcurrentHolder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "test.lock")
	l1, err := Acquire(p, DefaultTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(p, 100*time.Millisecond); err == nil {
		t.Fatal("a second Acquire should have blocked and timed out")
	}
	if err := l1.Release(); err != nil {
		t.Fatal(err)
	}
	l2, err := Acquire(p, DefaultTimeout)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	if err := l2.Release(); err != nil {
		t.Fatal(err)
	}
}

// TestConcurrentGoroutinesSerialize is the goroutine-level counterpart to
// the e2e concurrency tests: N goroutines race to hold the same lock and
// each marks (with an atomic CAS, so the check itself never races the Go
// race detector — the property under test is flock's mutual exclusion, not
// Go's) whether it found the "in critical section" flag already set by
// somebody else when it entered. If flock ever let two holders in at once,
// overlapped ends up true. Run under -race.
func TestConcurrentGoroutinesSerialize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "test.lock")
	const n = 50
	var inSection, overlapped int32
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l, err := Acquire(p, DefaultTimeout)
			if err != nil {
				errs[i] = err
				return
			}
			if !atomic.CompareAndSwapInt32(&inSection, 0, 1) {
				atomic.StoreInt32(&overlapped, 1)
			}
			time.Sleep(2 * time.Millisecond)
			atomic.StoreInt32(&inSection, 0)
			_ = l.Release()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if atomic.LoadInt32(&overlapped) != 0 {
		t.Fatal("two goroutines held the lock at once")
	}
}
