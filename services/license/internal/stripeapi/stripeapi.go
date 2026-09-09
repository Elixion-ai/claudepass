// Package stripeapi is the license service's narrow window onto Stripe: the
// two calls it makes (create a Checkout Session, create a Billing Portal
// session) live behind interfaces so every handler test runs against a fake
// and never touches the network. Webhook signature verification and event
// parsing use the stripe-go root package's ConstructEvent directly, since
// that call is pure (no network) and needs no seam.
package stripeapi

import (
	"context"
	"fmt"

	"github.com/stripe/stripe-go/v86"
)

// CheckoutCreator creates a Stripe Checkout Session and returns the URL to
// redirect the browser to.
type CheckoutCreator interface {
	NewCheckoutSession(ctx context.Context, email string) (url string, err error)
}

// PortalCreator creates a Stripe Billing Portal session and returns the URL
// to redirect (or link) the browser to.
type PortalCreator interface {
	NewPortalSession(ctx context.Context, customerID string) (url string, err error)
}

// Client is the real Stripe-backed implementation of CheckoutCreator and
// PortalCreator, used only by main.go; every test uses a fake instead.
type Client struct {
	sc      *stripe.Client
	priceID string
	baseURL string
}

// New builds a Client. secretKey is the Stripe secret API key, priceID the
// recurring Price for the $9.99/month plan, and baseURL this service's own
// public URL (no trailing slash) used to build success/return URLs.
func New(secretKey, priceID, baseURL string) *Client {
	return &Client{sc: stripe.NewClient(secretKey), priceID: priceID, baseURL: baseURL}
}

// NewCheckoutSession creates a subscription-mode Checkout Session for the
// configured price. The success URL carries Stripe's own
// {CHECKOUT_SESSION_ID} placeholder, which Stripe substitutes with the real
// session id on redirect — that id is what GET /license?session_id= looks
// up.
func (c *Client) NewCheckoutSession(ctx context.Context, email string) (string, error) {
	params := &stripe.CheckoutSessionCreateParams{
		Mode:       stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		SuccessURL: stripe.String(c.baseURL + "/license?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(c.baseURL + "/checkout/canceled"),
		LineItems: []*stripe.CheckoutSessionCreateLineItemParams{
			{Price: stripe.String(c.priceID), Quantity: stripe.Int64(1)},
		},
	}
	if email != "" {
		params.CustomerEmail = stripe.String(email)
	}
	session, err := c.sc.V1CheckoutSessions.Create(ctx, params)
	if err != nil {
		return "", fmt.Errorf("stripeapi: create checkout session: %w", err)
	}
	return session.URL, nil
}

// NewPortalSession creates a Billing Portal session for customerID,
// returning to this service's /license page.
func (c *Client) NewPortalSession(ctx context.Context, customerID string) (string, error) {
	params := &stripe.BillingPortalSessionCreateParams{
		Customer:  stripe.String(customerID),
		ReturnURL: stripe.String(c.baseURL + "/"),
	}
	session, err := c.sc.V1BillingPortalSessions.Create(ctx, params)
	if err != nil {
		return "", fmt.Errorf("stripeapi: create portal session: %w", err)
	}
	return session.URL, nil
}
