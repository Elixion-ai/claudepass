package server

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"time"

	"claudepass/services/license/internal/store"
)

// handleLicensePage is Stripe Checkout's success_url target
// (GET /license?session_id={CHECKOUT_SESSION_ID}). It shows the issued
// token exactly once, as the `cpass license activate` command to run, then
// clears it from the store: a reload, or anyone else with the URL, sees
// only the "already shown" page, never the token again.
func (s *Server) handleLicensePage(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}

	token, err := s.takeTokenWithRetry(r.Context(), sessionID)
	switch {
	case err == nil:
		writeTokenPage(w, token)
	case errors.Is(err, store.ErrTokenAlreadyShown):
		writeAlreadyShownPage(w)
	case errors.Is(err, store.ErrTokenNotFound):
		http.Error(w,
			"checkout is still being processed; reload this page in a few seconds, or use POST /reissue with the email you subscribed with",
			http.StatusNotFound)
	default:
		s.log.Error("license page", "session_id", sessionID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// takeTokenWithRetry polls the store for a short, bounded window: it
// retries only on "not found yet" (the webhook has not landed), never on
// "already shown", which is a terminal answer.
func (s *Server) takeTokenWithRetry(ctx context.Context, sessionID string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < s.tokenPollAttempts; attempt++ {
		token, err := s.store.TakeCheckoutToken(ctx, sessionID)
		if err == nil {
			return token, nil
		}
		if !errors.Is(err, store.ErrTokenNotFound) {
			return "", err
		}
		lastErr = err
		if attempt < s.tokenPollAttempts-1 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(s.tokenPollInterval):
			}
		}
	}
	return "", lastErr
}

func writeTokenPage(w http.ResponseWriter, token string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// token's alphabet is base64url plus one '.' separator, which needs no
	// HTML escaping, but this escapes it anyway so nothing here ever
	// depends on that being true.
	fmt.Fprintf(w, `<!doctype html>
<title>ClaudePass license</title>
<p>Your ClaudePass license is ready. Run this once, on the machine where you use ClaudePass:</p>
<pre>cpass license activate %s</pre>
<p>This page will not show the token again — copy the command now. If you lose it, use <code>POST /reissue</code> with the email you subscribed with, or manage your subscription in the Stripe customer portal.</p>
`, html.EscapeString(token))
}

func writeAlreadyShownPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<!doctype html>
<title>ClaudePass license</title>
<p>This license was already shown once and cannot be displayed again.</p>
<p>Lost it? Use <code>POST /reissue</code> with the email you subscribed with.</p>
`)
}
