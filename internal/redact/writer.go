// Package redact replaces Secret values, in every recognisable encoding, with
// a marker in a byte stream before that stream can reach an Agent.
//
// The Writer is streaming: every byte is forwarded as soon as it cannot be
// the start of a Pattern. Only a suffix that is a genuine prefix of some
// Pattern is held back, and even that is released after an idle period so
// interactive tools stay responsive.
package redact

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// Event records one redaction, for the log. It never carries the value.
type Event struct {
	Handle   string
	Encoding string
	Stream   string
}

// Writer is an io.WriteCloser that redacts Patterns on the way to dst.
type Writer struct {
	dst      io.Writer
	stream   string
	patterns []Pattern
	ac       *automaton // nil when patterns is empty
	onEvent  func(Event)

	mu       sync.Mutex
	held     []byte // suffix that may still complete a Pattern
	heldAt   time.Time
	timer    *time.Timer
	matchBuf []acMatch // scratch, reused across scan calls
	closed   bool
	writeErr error
}

// Idle periods after which a held partial match is released unmatched. A
// short partial (a prompt that happens to share a Secret's first bytes) is
// released quickly; a longer one is held longer because chunked writes of
// a real value are the more likely explanation.
const (
	ShortPartial   = 4
	IdleFlushShort = 100 * time.Millisecond
	IdleFlushLong  = 1500 * time.Millisecond
)

// NewWriter wraps dst. stream names it in events ("stdout"/"stderr").
func NewWriter(dst io.Writer, stream string, patterns []Pattern, onEvent func(Event)) *Writer {
	w := &Writer{dst: dst, stream: stream, patterns: patterns, onEvent: onEvent}
	if len(patterns) > 0 {
		w.ac = buildAutomaton(patterns)
	}
	return w
}

// Marker is the replacement text for a redacted value.
func Marker(handle string) []byte { return []byte("[REDACTED:" + handle + "]") }

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	// The common case carries nothing over from the last Write: scan p
	// directly rather than copying it onto an empty w.held first.
	buf := p
	if len(w.held) > 0 {
		buf = append(w.held, p...)
	}
	w.held = nil
	out, rest := w.scan(buf)
	if len(out) > 0 {
		if _, err := w.dst.Write(out); err != nil {
			w.writeErr = err
			return 0, err
		}
	}
	if len(rest) > 0 {
		w.held = append([]byte(nil), rest...)
		w.heldAt = time.Now()
		d := IdleFlushLong
		if len(rest) < ShortPartial {
			d = IdleFlushShort
		}
		w.timer = time.AfterFunc(d, w.idleFlush)
	}
	return len(p), nil
}

// scan replaces complete matches in buf and returns the bytes safe to emit
// and the suffix that must be held because it could still complete a match.
//
// A single Aho-Corasick walk (automaton.find) locates every occurrence of
// every Pattern in one pass over buf, however many Secrets are loaded; scan
// then resolves those (possibly overlapping) occurrences to the
// leftmost-longest, non-overlapping set: at each position take the earliest
// occurrence, and the longest of any that start there, exactly as the
// original per-pattern bytes.Index loop did, but without repeating the scan
// once per pattern.
func (w *Writer) scan(buf []byte) (out, rest []byte) {
	if w.ac == nil {
		return buf, nil
	}
	w.matchBuf = w.ac.find(buf, w.matchBuf[:0])
	if len(w.matchBuf) == 0 {
		// Nothing matched: no marker to write, so skip the copy entirely and
		// just find how much of the end must be held back.
		hold := w.ac.partialLen(buf)
		return buf[:len(buf)-hold], buf[len(buf)-hold:]
	}
	sort.Slice(w.matchBuf, func(i, j int) bool {
		a, b := w.matchBuf[i], w.matchBuf[j]
		if a.start != b.start {
			return a.start < b.start
		}
		if a.length != b.length {
			return a.length > b.length // longest wins ties on the same start
		}
		return a.pidx < b.pidx // stable: first pattern in list order wins
	})
	var res bytes.Buffer
	cursor := 0
	for _, m := range w.matchBuf {
		if m.start < cursor {
			continue // overlaps a match already emitted
		}
		res.Write(buf[cursor:m.start])
		pat := w.patterns[m.pidx]
		res.Write(Marker(pat.Handle))
		if w.onEvent != nil {
			w.onEvent(Event{Handle: pat.Handle, Encoding: pat.Encoding, Stream: w.stream})
		}
		cursor = m.start + m.length
	}
	tail := buf[cursor:]
	hold := w.ac.partialLen(tail)
	res.Write(tail[:len(tail)-hold])
	return res.Bytes(), tail[len(tail)-hold:]
}

func (w *Writer) idleFlush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || len(w.held) == 0 {
		return
	}
	held := w.held
	w.held = nil
	w.timer = nil
	if _, err := w.dst.Write(held); err != nil {
		w.writeErr = err
	}
}

// Close releases any held bytes (they did not complete a match) and marks
// the writer closed.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.timer != nil {
		w.timer.Stop()
	}
	if len(w.held) > 0 {
		if _, err := w.dst.Write(w.held); err != nil {
			w.writeErr = err
		}
		w.held = nil
	}
	return w.writeErr
}

// Log appends events to an append-only file, one line each, never the value.
type Log struct {
	mu   sync.Mutex
	path string
	cmd  string
	cnt  map[string]int
}

// NewLog creates a Log writing to path for a command named cmd.
func NewLog(path, cmd string) *Log { return &Log{path: path, cmd: cmd, cnt: map[string]int{}} }

// Record writes one event line and counts it.
func (l *Log) Record(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cnt[e.Handle]++
	if l.path == "" {
		return
	}
	f, err := openAppend(l.path)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s handle=%s encoding=%s stream=%s cmd=%s\n",
		time.Now().UTC().Format(time.RFC3339), e.Handle, e.Encoding, e.Stream, l.cmd)
}

// Counts returns redactions per Handle.
func (l *Log) Counts() map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]int, len(l.cnt))
	for k, v := range l.cnt {
		out[k] = v
	}
	return out
}
