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
	maxLen   int
	first    [256]bool
	onEvent  func(Event)

	mu       sync.Mutex
	held     []byte // suffix that may still complete a Pattern
	heldAt   time.Time
	timer    *time.Timer
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
	for _, p := range patterns {
		if len(p.Bytes) > w.maxLen {
			w.maxLen = len(p.Bytes)
		}
		w.first[p.Bytes[0]] = true
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
	buf := append(w.held, p...)
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
func (w *Writer) scan(buf []byte) (out, rest []byte) {
	if len(w.patterns) == 0 {
		return buf, nil
	}
	var res bytes.Buffer
	i := 0
	for i < len(buf) {
		// Find the leftmost match at or after i, longest wins on ties.
		mi, mp := -1, -1
		for pi := range w.patterns {
			pb := w.patterns[pi].Bytes
			j := bytes.Index(buf[i:], pb)
			if j < 0 {
				continue
			}
			j += i
			if mi < 0 || j < mi || (j == mi && len(pb) > len(w.patterns[mp].Bytes)) {
				mi, mp = j, pi
			}
		}
		if mi < 0 {
			break
		}
		res.Write(buf[i:mi])
		pat := w.patterns[mp]
		res.Write(Marker(pat.Handle))
		if w.onEvent != nil {
			w.onEvent(Event{Handle: pat.Handle, Encoding: pat.Encoding, Stream: w.stream})
		}
		i = mi + len(pat.Bytes)
	}
	tail := buf[i:]
	hold := w.partialAt(tail)
	res.Write(tail[:len(tail)-hold])
	return res.Bytes(), tail[len(tail)-hold:]
}

// partialAt returns the length of the longest suffix of tail that is a
// proper prefix of some Pattern.
func (w *Writer) partialAt(tail []byte) int {
	start := len(tail) - (w.maxLen - 1)
	if start < 0 {
		start = 0
	}
	for i := start; i < len(tail); i++ {
		if !w.first[tail[i]] {
			continue
		}
		suffix := tail[i:]
		for _, p := range w.patterns {
			if len(p.Bytes) > len(suffix) && bytes.HasPrefix(p.Bytes, suffix) {
				return len(suffix)
			}
		}
	}
	return 0
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
