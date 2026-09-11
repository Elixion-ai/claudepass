package server

import (
	"errors"
	"net/http"

	"claudepass/services/license/internal/mailer"
	"claudepass/services/license/internal/pages"
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
		pages.ReissueMissingEmail(w)
		return
	}

	ctx := r.Context()
	cust, err := s.store.CustomerByEmail(ctx, email)
	if errors.Is(err, store.ErrCustomerNotFound) {
		pages.ReissueNotFound(w)
		return
	}
	if err != nil {
		s.log.Error("reissue: look up customer", "error", err)
		pages.InternalError(w)
		return
	}
	if cust.Status != store.StatusActive {
		pages.ReissueInactive(w, int(GracePeriod.Hours()/24))
		return
	}

	minted, err := s.issueToken(cust.Email, cust.PeriodEnd)
	if err != nil {
		s.log.Error("reissue: mint token", "error", err)
		pages.InternalError(w)
		return
	}
	if err := s.store.RecordIssuedToken(ctx, minted.JTI, cust.CustomerID, s.now().Unix(), minted.Exp); err != nil {
		s.log.Error("reissue: record issued token", "error", err)
		pages.InternalError(w)
		return
	}

	var portalURL string
	if s.portal != nil {
		if u, err := s.portal.NewPortalSession(ctx, cust.CustomerID); err == nil {
			portalURL = u
		} else {
			s.log.Warn("reissue: create portal session", "error", err)
		}
	}

	text, html := mailer.ReissueEmail(minted.Token, portalURL)
	if err := s.mail.Send(ctx, cust.Email, "Your ClaudePass license", text, html); err != nil {
		s.log.Error("reissue: send email", "error", err)
		pages.ReissueMailFailed(w)
		return
	}

	pages.ReissueSent(w)
}
