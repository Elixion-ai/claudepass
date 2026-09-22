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

// TestLogRecordManyMatchesOpensOnce covers CLA-70: the per-event
// open+write+close this ticket removed measured ~17.6us/event (~1.76s for
// 100,000 events). It asserts the mechanism — one *os.File, opened on the
// first Record and reused for every later one — rather than a wall-clock
// bound, which flaked under -race on a loaded host; the elapsed time is
// logged for anyone comparing against BenchmarkLogRecord.
func TestLogRecordManyMatchesOpensOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redactions.log")
	l := NewLog(path, "cmd")
	defer func() { _ = l.Close() }()

	l.Record(Event{Handle: "h", Encoding: "raw", Stream: "stdout"})
	first := l.f
	if first == nil {
		t.Fatal("Record did not open the log file")
	}

	const n = 100_000
	start := time.Now()
	for i := 1; i < n; i++ {
		l.Record(Event{Handle: "h", Encoding: "raw", Stream: "stdout"})
		if l.f != first {
			t.Fatalf("Record %d reopened the log file; it must stay open for the Log's lifetime", i)
		}
	}
	elapsed := time.Since(start)
	t.Logf("%d Record calls in %v (%.2f us/event)", n, elapsed, float64(elapsed.Microseconds())/n)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(raw), "handle=h"); got != n {
		t.Fatalf("log has %d events, want %d", got, n)
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
