package server

import (
	"errors"
	"fmt"
	"net/http"

	"claudepass/services/license/internal/store"
)

// handleReissue mints a fresh token for an existing, still-active
// subscriber and emails it — it never returns the token in the HTTP
// response, so a browser history entry or a reverse-proxy access log can
// never carry one. A canceled subscription (customer.subscription.deleted
// having landed) is refused here: this is the CLA-15 acceptance behaviour
// "subscription deleted -> next reissue refused". The email also carries a
// link to the Stripe customer portal so the subscriber can manage or
// resume billing from the same message.
func (s *Server) handleReissue(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "missing email", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	cust, err := s.store.CustomerByEmail(ctx, email)
	if errors.Is(err, store.ErrCustomerNotFound) {
		http.Error(w, "no subscription found for that email", http.StatusNotFound)
		return
	}
	if err != nil {
		s.log.Error("reissue: look up customer", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if cust.Status != store.StatusActive {
		http.Error(w, "subscription is not active; reissue refused", http.StatusPaymentRequired)
		return
	}

	minted, err := s.issueToken(cust.Email, cust.PeriodEnd)
	if err != nil {
		s.log.Error("reissue: mint token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.RecordIssuedToken(ctx, minted.JTI, cust.CustomerID, s.now().Unix(), minted.Exp); err != nil {
		s.log.Error("reissue: record issued token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	body := fmt.Sprintf("Your fresh ClaudePass license. Run this on the machine where you use ClaudePass:\n\n    cpass license activate %s\n", minted.Token)
	if s.portal != nil {
		if portalURL, err := s.portal.NewPortalSession(ctx, cust.CustomerID); err == nil {
			body += fmt.Sprintf("\nManage your subscription: %s\n", portalURL)
		} else {
			s.log.Warn("reissue: create portal session", "error", err)
		}
	}

	if err := s.mail.Send(ctx, cust.Email, "Your ClaudePass license", body); err != nil {
		s.log.Error("reissue: send email", "error", err)
		http.Error(w, "could not send the email; try again shortly", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, "a fresh license has been emailed to you") // best-effort: nothing left to do with a broken response write
}
