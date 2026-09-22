package mcp

import "encoding/json"

// cancel.go tracks the requests callAsync (below) runs in their own
// goroutine — run_with_secrets and capture, the two tool calls that block
// on a child process — so a matching notifications/cancelled (CLA-76) can
// reach one still running and, per the MCP Cancellation spec, guarantee no
// response is ever sent for it.

// idKey turns a JSON-RPC id into a comparable map key. Two different
// requests never share an id within one session (the client's own
// responsibility per JSON-RPC 2.0), so the id's raw JSON text is already
// unique and needs no parsing — this does assume a client renders the same
// logical id identically in a request and in that request's own
// notifications/cancelled (e.g. always 7, never 7 and then 7.0), which
// every real client does since both come from the one value it is
// tracking.
func idKey(id json.RawMessage) string { return string(id) }

// beginCancellable registers id as in-flight and returns the channel a
// cancellation closes (pass it to run.Spec.Cancel) and a cleanup func the
// caller must defer once its call finishes, cancelled or not, so a
// notifications/cancelled arriving after that point finds nothing left to
// signal.
//
// done also clears cancelled[key] (CLA-98 item 5). Without that, a
// notifications/cancelled that lands after the call's response has already
// been written — suppressed (below) already had nothing to consume, since
// it runs before cancelled[key] could ever be set — but before this done()
// runs sets cancelled[key] = true in handleCancelled and finds inflight
// still registered, since removing it is done's job, not
// handleCancelled's. Nothing will ever call suppressed for this id again,
// so that entry would otherwise sit in the map for the rest of the
// session.
func (s *server) beginCancellable(id json.RawMessage) (cancel chan struct{}, done func()) {
	cancel = make(chan struct{})
	key := idKey(id)
	s.cancelMu.Lock()
	s.inflight[key] = cancel
	s.cancelMu.Unlock()
	return cancel, func() {
		s.cancelMu.Lock()
		if s.inflight[key] == cancel { // only remove our own registration
			delete(s.inflight, key)
		}
		delete(s.cancelled, key)
		s.cancelMu.Unlock()
	}
}

// handleCancelled implements notifications/cancelled: closing the
// matching in-flight call's cancel channel (run.Spec.Cancel sees this and
// kills the child — internal/run/run.go) and marking its eventual response
// to be dropped instead of sent. An id that is not (or no longer)
// in-flight — never registered, or already finished — is left alone: the
// MCP Cancellation spec allows a server to ignore cancellation for an
// unknown or already-completed request, and there is nothing left here to
// signal or suppress for one anyway.
func (s *server) handleCancelled(req request) {
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &p)
	}
	if len(p.RequestID) == 0 {
		return
	}
	key := idKey(p.RequestID)
	s.cancelMu.Lock()
	ch, ok := s.inflight[key]
	if ok {
		delete(s.inflight, key)
		s.cancelled[key] = true
	}
	s.cancelMu.Unlock()
	if ok {
		close(ch)
	}
}

// suppressed reports whether id was cancelled (handleCancelled above), and
// if so consumes that fact so it cannot suppress some later, unrelated
// response that happens to reuse the same id text. writeResult/writeError
// (server.go) are the only callers.
func (s *server) suppressed(id json.RawMessage) bool {
	key := idKey(id)
	s.cancelMu.Lock()
	defer s.cancelMu.Unlock()
	if s.cancelled[key] {
		delete(s.cancelled, key)
		return true
	}
	return false
}

// callAsync runs fn — a full tool-call handler that ends by writing its own
// response via writeResult/writeError, exactly like every synchronous one —
// in its own goroutine, tracked by req's id via beginCancellable so
// handleCancelled can reach it. It is only for run_with_secrets and
// capture (handleToolsCall in tools.go): every other method stays
// synchronous, so its response is written, and the next stdin line read,
// before this one even starts.
func (s *server) callAsync(id json.RawMessage, fn func(cancel <-chan struct{})) {
	cancel, done := s.beginCancellable(id)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer done()
		fn(cancel)
	}()
}
