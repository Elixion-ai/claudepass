package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"claudepass/services/license/internal/pages"
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
		pages.LicenseInvalid(w)
		return
	}

	ct, err := s.takeTokenWithRetry(r.Context(), sessionID)
	switch {
	case err == nil:
		pages.LicenseReady(w, ct.Token, ct.Email, ct.PeriodEnd)
	case errors.Is(err, store.ErrTokenAlreadyShown):
		pages.LicenseAlreadyShown(w)
	case errors.Is(err, store.ErrTokenNotFound):
		pages.LicensePending(w, sessionID)
	default:
		s.log.Error("license page", "session_id", sessionID, "error", err)
		pages.InternalError(w)
	}
}

// takeTokenWithRetry polls the store for a short, bounded window: it
// retries only on "not found yet" (the webhook has not landed), never on
// "already shown", which is a terminal answer.
func (s *Server) takeTokenWithRetry(ctx context.Context, sessionID string) (store.CheckoutToken, error) {
	var lastErr error
	for attempt := 0; attempt < s.tokenPollAttempts; attempt++ {
		ct, err := s.store.TakeCheckoutToken(ctx, sessionID)
		if err == nil {
			return ct, nil
		}
		if !errors.Is(err, store.ErrTokenNotFound) {
			return store.CheckoutToken{}, err
		}
		lastErr = err
		if attempt < s.tokenPollAttempts-1 {
			select {
			case <-ctx.Done():
				return store.CheckoutToken{}, ctx.Err()
			case <-time.After(s.tokenPollInterval):
			}
		}
	}
	return store.CheckoutToken{}, lastErr
}
