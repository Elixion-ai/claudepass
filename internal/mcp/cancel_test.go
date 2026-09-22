package mcp

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestDoneClearsOrphanedCancelledEntry is CLA-98 item 5's regression test.
// It reproduces the race directly, by ordering, rather than relying on
// real goroutine timing: notifications/cancelled arrives for an id that is
// still registered in inflight (i.e. before its call's own done() has run)
// but after that call's response was already written -- suppressed was
// never called to consume the cancelled flag handleCancelled is about to
// set, since a response only calls it once, before this point. Without
// item 5's fix, that cancelled[key] entry outlives done() and leaks for
// the rest of the session, since nothing will ever call suppressed for
// this id again.
func TestDoneClearsOrphanedCancelledEntry(t *testing.T) {
	s := newServer(&bytes.Buffer{}, "test")
	id := json.RawMessage(`7`)
	_, done := s.beginCancellable(id)

	// The call's response has already gone out (imagine writeResult ran
	// just before this line); notifications/cancelled for the same id
	// arrives next, while done() -- the goroutine's own deferred cleanup --
	// has not run yet.
	s.handleCancelled(request{Params: json.RawMessage(`{"requestId":7}`)})

	key := idKey(id)
	s.cancelMu.Lock()
	_, setByCancellation := s.cancelled[key]
	s.cancelMu.Unlock()
	if !setByCancellation {
		t.Fatalf("handleCancelled should have set cancelled[%q] while %q was still in-flight", key, key)
	}

	done()

	s.cancelMu.Lock()
	_, leftover := s.cancelled[key]
	_, stillInflight := s.inflight[key]
	s.cancelMu.Unlock()
	if leftover {
		t.Fatalf("cancelled[%q] leaked after done(): no future response for this id will ever consume it", key)
	}
	if stillInflight {
		t.Fatalf("inflight[%q] should also be gone after done()", key)
	}
}

// TestDoneLeavesUnrelatedCancelledEntriesAlone guards against an
// over-broad fix: done() must delete only its own id's cancelled entry,
// never another in-flight call's.
func TestDoneLeavesUnrelatedCancelledEntriesAlone(t *testing.T) {
	s := newServer(&bytes.Buffer{}, "test")
	idA := json.RawMessage(`7`)
	idB := json.RawMessage(`8`)
	_, doneA := s.beginCancellable(idA)
	_, doneB := s.beginCancellable(idB)

	s.handleCancelled(request{Params: json.RawMessage(`{"requestId":7}`)})
	s.handleCancelled(request{Params: json.RawMessage(`{"requestId":8}`)})

	doneA()

	keyB := idKey(idB)
	s.cancelMu.Lock()
	_, stillSet := s.cancelled[keyB]
	s.cancelMu.Unlock()
	if !stillSet {
		t.Fatalf("done() for id 7 must not clear cancelled[%q] (id 8's own entry)", keyB)
	}
	doneB()
}
