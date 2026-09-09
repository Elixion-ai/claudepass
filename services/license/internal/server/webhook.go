package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/stripe/stripe-go/v86"

	"claudepass/services/license/internal/store"
)

// maxWebhookBody bounds how much of a webhook request body is read. Stripe
// event payloads are a few KB; this is generous headroom against a
// misbehaving or malicious sender.
const maxWebhookBody = 1 << 20 // 1 MiB

// handleWebhook verifies and dispatches a Stripe webhook delivery.
// checkout.session.completed issues the first token for a new customer;
// customer.subscription.updated refreshes the known period end and status;
// customer.subscription.deleted marks the customer canceled, which is what
// makes the next POST /reissue refuse (CLA-15 acceptance). Every other
// event type is acknowledged and ignored: Stripe only retries on a
// non-2xx response.
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxWebhookBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}

	event, err := stripe.ConstructEvent(body, r.Header.Get("Stripe-Signature"), s.webhookSecret,
		stripe.WithIgnoreAPIVersionMismatch())
	if err != nil {
		s.log.Warn("webhook signature rejected", "error", err)
		http.Error(w, "signature verification failed", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	now := s.now().Unix()

	switch event.Type {
	case stripe.EventTypeCheckoutSessionCompleted:
		err = s.handleCheckoutCompleted(ctx, event, now)
	case stripe.EventTypeCustomerSubscriptionUpdated:
		err = s.handleSubscriptionEvent(ctx, event, now, store.StatusActive)
	case stripe.EventTypeCustomerSubscriptionDeleted:
		err = s.handleSubscriptionEvent(ctx, event, now, store.StatusCanceled)
	default:
		// Ignored on purpose: this endpoint only needs the three event
		// types above. Still recorded, so a redelivery of an ignored event
		// doesn't do even the (harmless) work of re-deciding to ignore it.
		err = s.store.MarkEventProcessed(ctx, event.ID, now)
	}
	if errors.Is(err, store.ErrAlreadyProcessed) {
		w.WriteHeader(http.StatusOK)
		return
	}
	if err != nil {
		s.log.Error("process webhook", "event", event.ID, "type", string(event.Type), "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleCheckoutCompleted issues the customer's first token. The
// subscription reference on a checkout.session.completed event is not
// expanded by default, so the exact period end is usually unknown at this
// point; issueToken falls back to a one-month default in that case, and
// the customer.subscription.updated event Stripe sends moments later (a
// side effect of the same checkout) refines Store's period_end for future
// reissues.
func (s *Server) handleCheckoutCompleted(ctx context.Context, event stripe.Event, now int64) error {
	var session stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
		return err
	}
	if session.Mode != stripe.CheckoutSessionModeSubscription {
		return nil // not our $9.99/month subscription flow
	}

	email := session.CustomerEmail
	if session.CustomerDetails != nil && session.CustomerDetails.Email != "" {
		email = session.CustomerDetails.Email
	}
	var customerID string
	if session.Customer != nil {
		customerID = session.Customer.ID
	}
	if email == "" || customerID == "" || session.ID == "" {
		return errors.New("checkout.session.completed missing customer, email, or session id")
	}

	var periodEnd int64
	if session.Subscription != nil {
		periodEnd = subscriptionPeriodEnd(session.Subscription)
	}

	minted, err := s.issueToken(email, periodEnd)
	if err != nil {
		return err
	}
	return s.store.IssueForCheckout(ctx, store.IssuedToken{
		EventID: event.ID, SessionID: session.ID, CustomerID: customerID, Email: email,
		PeriodEnd: periodEnd, Now: now, Token: minted.Token, JTI: minted.JTI, Exp: minted.Exp,
	})
}

// handleSubscriptionEvent applies a customer.subscription.updated or
// .deleted event: it updates the stored status and, when known, period
// end. It never mints a token — a renewal or a lost token is fetched by
// the customer through POST /reissue, keyed off this stored state.
func (s *Server) handleSubscriptionEvent(ctx context.Context, event stripe.Event, now int64, status string) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		return err
	}
	if sub.ID == "" || sub.Customer == nil || sub.Customer.ID == "" {
		return errors.New("subscription event missing subscription or customer id")
	}
	periodEnd := subscriptionPeriodEnd(&sub)
	return s.store.UpdateSubscription(ctx, event.ID, sub.Customer.ID, sub.ID, status, periodEnd, now)
}

// subscriptionPeriodEnd returns the current period end of a subscription's
// first (and, for this single-price plan, only) item, or 0 if the
// subscription was not expanded enough to carry it.
func subscriptionPeriodEnd(sub *stripe.Subscription) int64 {
	if sub.Items == nil || len(sub.Items.Data) == 0 {
		return 0
	}
	return sub.Items.Data[0].CurrentPeriodEnd
}
