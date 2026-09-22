package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLogOpensFileOnceAcrossRecords covers CLA-70: Record must open
// redactions.log at most once across many events, not once per event.
// Directly inspecting the unexported *os.File field is the simplest way to
// prove "opened once, kept open" rather than "reopened but the content
// still happens to look right" — the two are indistinguishable from the
// file's content alone.
func TestLogOpensFileOnceAcrossRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redactions.log")
	l := NewLog(path, "cmd")

	l.Record(Event{Handle: "h", Encoding: "raw", Stream: "stdout"})
	f1 := l.f
	if f1 == nil {
		t.Fatal("Record did not open the log file on first use")
	}
	for i := 0; i < 20; i++ {
		l.Record(Event{Handle: "h", Encoding: "raw", Stream: "stdout"})
		if l.f != f1 {
			t.Fatalf("Record %d reopened the log file instead of reusing the one it already had open", i)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if l.f != nil {
		t.Fatal("Close did not release the file handle")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "handle=h"); got != 21 {
		t.Fatalf("log has %d events, want 21", got)
	}
}

// TestLogCloseWithNoEventsIsANoOp covers TestNoRedactionNoNoise's e2e
// invariant (internal/e2e/leak_test.go) at this package's level: a Log that
// never saw a Record call (nothing was redacted) must not create the file,
// and Close on it must not error just because there was never anything to
// close.
func TestLogCloseWithNoEventsIsANoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redactions.log")
	l := NewLog(path, "cmd")
	if err := l.Close(); err != nil {
		t.Fatalf("Close on an untouched Log: %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("Close must not create the log file when nothing was ever recorded")
	}
}

// TestLogRecordAfterCloseReopens covers the boundary Log's contract leaves
// open: Close is meant to run once, at the end of the Run invocation that
// owns this Log, but a Record call after it must still degrade safely
// (reopen) rather than silently drop the event or panic.
func TestLogRecordAfterCloseReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redactions.log")
	l := NewLog(path, "cmd")
	l.Record(Event{Handle: "h", Encoding: "raw", Stream: "stdout"})
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	l.Record(Event{Handle: "h", Encoding: "raw", Stream: "stdout"})
	defer func() { _ = l.Close() }()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "handle=h"); got != 2 {
		t.Fatalf("log has %d events, want 2: %s", got, raw)
	}
}

// TestLogRecordManyMatchesFast covers CLA-70's acceptance bar as a real,
// always-run check rather than a benchmark number someone has to eyeball
// (mirroring TestThroughputMeetsBar in redact_test.go): the per-event
// open+write+close overhead this ticket fixes measured ~17.6us/event before
// the fix, i.e. ~1.76s for 100,000 events; opening the file once and
// reusing it should leave only the (unavoidable) per-event write syscall,
// well under a tenth of that old total on any host, loaded or not.
func TestLogRecordManyMatchesFast(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redactions.log")
	l := NewLog(path, "cmd")
	defer func() { _ = l.Close() }()

	const n = 100_000
	const bound = 500 * time.Millisecond // generous even under host contention; ~1.76s was the old per-open-per-event cost

	start := time.Now()
	for i := 0; i < n; i++ {
		l.Record(Event{Handle: "h", Encoding: "raw", Stream: "stdout"})
	}
	elapsed := time.Since(start)
	t.Logf("%d Record calls in %v (%.2f us/event)", n, elapsed, float64(elapsed.Microseconds())/n)
	if elapsed > bound {
		t.Fatalf("%d Record calls took %v, want under %v — the log file is being reopened per event again", n, elapsed, bound)
	}
}

// BenchmarkLogRecord measures Log.Record's per-event cost against a real
// file with many matches, the ticket's own before/after comparison point.
func BenchmarkLogRecord(b *testing.B) {
	path := filepath.Join(b.TempDir(), "redactions.log")
	l := NewLog(path, "cmd")
	defer func() { _ = l.Close() }()
	e := Event{Handle: "h", Encoding: "raw", Stream: "stdout"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Record(e)
	}
}
