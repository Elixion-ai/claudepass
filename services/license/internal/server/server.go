// Package server implements the license service's HTTP surface:
// POST /checkout, POST /webhook, GET /license, POST /reissue. It is the
// piece under test in every *_test.go in this directory; main.go only
// wires real dependencies and calls Handler().
//
// Standing rule for every file in this package: a license token (the
// string internal/license.Sign returns) may be written into an HTTP
// response body and into the store's checkout_tokens.token column. It must
// never reach a log call. See the leak-style check in webhook_test.go.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"claudepass/internal/license"
	"claudepass/services/license/internal/mailer"
	"claudepass/services/license/internal/store"
)

// GracePeriod is added to a subscription's known period end when minting a
// token's exp, per ADR-0006 / CLA-15: no revocation list, tokens simply
// carry a short grace window past the paid period and get reissued.
const GracePeriod = 3 * 24 * time.Hour

// defaultPeriod is used for the token minted at checkout.session.completed
// when the event does not carry an expanded subscription (Stripe does not
// expand `subscription` on that event by default): one month, matching the
// $9.99/month plan, plus GracePeriod. customer.subscription.updated
// refines Store's period_end once Stripe sends the real value; a renewal
// or a lost token is recovered via POST /reissue.
const defaultPeriod = 31 * 24 * time.Hour

// Deps are the Server's dependencies. Every field is required except
// Mailer, which may be mailer.NoopMailer{} (the default when SMTP is not
// configured); Reissue then refuses with a clear error instead of
// discarding a token nobody can receive.
type Deps struct {
	Store      *store.Store
	Checkout   CheckoutCreator
	Portal     PortalCreator
	Mailer     mailer.Mailer
	SigningKey ed25519.PrivateKey
	// WebhookSecret verifies the Stripe-Signature header.
	WebhookSecret string
	// BaseURL is this service's own public URL (no trailing slash).
	BaseURL string
	// Logger receives structured, token-free operational logs. Defaults to
	// slog.Default() when nil.
	Logger *slog.Logger
	// Now returns the current time; defaults to time.Now. Tests override
	// it to control expiry math deterministically.
	Now func() time.Time

	// TokenPollInterval and TokenPollAttempts bound how long GET /license
	// waits for a Checkout Session's webhook to land before giving up.
	// Stripe typically delivers checkout.session.completed well before (or
	// around) the browser's own redirect to success_url, but nothing
	// guarantees the order, so a short bounded poll absorbs the race
	// without an extra Stripe API call. Both default when zero.
	TokenPollInterval time.Duration
	TokenPollAttempts int
}

// CheckoutCreator and PortalCreator mirror stripeapi's interfaces so this
// package does not import stripeapi (and, transitively, stripe-go) at all
// — every test supplies a fake. main.go passes a *stripeapi.Client, which
// satisfies both.
type CheckoutCreator interface {
	NewCheckoutSession(ctx context.Context, email string) (url string, err error)
}

type PortalCreator interface {
	NewPortalSession(ctx context.Context, customerID string) (url string, err error)
}

// Server holds the resolved dependencies and builds the http.Handler.
type Server struct {
	store         *store.Store
	checkout      CheckoutCreator
	portal        PortalCreator
	mail          mailer.Mailer
	signingKey    ed25519.PrivateKey
	webhookSecret string
	baseURL       string
	log           *slog.Logger
	now           func() time.Time

	tokenPollInterval time.Duration
	tokenPollAttempts int
}

// New builds a Server from Deps, applying defaults for optional fields.
func New(d Deps) *Server {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Mailer == nil {
		d.Mailer = mailer.NoopMailer{}
	}
	if d.TokenPollInterval == 0 {
		d.TokenPollInterval = 200 * time.Millisecond
	}
	if d.TokenPollAttempts == 0 {
		d.TokenPollAttempts = 15 // ~3s total
	}
	return &Server{
		store:             d.Store,
		checkout:          d.Checkout,
		portal:            d.Portal,
		mail:              d.Mailer,
		signingKey:        d.SigningKey,
		webhookSecret:     d.WebhookSecret,
		baseURL:           d.BaseURL,
		log:               d.Logger,
		now:               d.Now,
		tokenPollInterval: d.TokenPollInterval,
		tokenPollAttempts: d.TokenPollAttempts,
	}
}

// Handler returns the service's http.Handler: routes wrapped in a request
// logging middleware that logs method, path and status only — never a
// query string (session_id is not secret, but this keeps the rule
// exceptionless) and never a body.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /checkout", s.handleCheckout)
	mux.HandleFunc("POST /webhook", s.handleWebhook)
	mux.HandleFunc("GET /license", s.handleLicensePage)
	mux.HandleFunc("POST /reissue", s.handleReissue)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	return s.logRequests(mux)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// mintedToken is a freshly signed token together with the fields the store
// needs to keep a customer->jti record (CLA-15: SQLite "stores
// customer→jti"), even though the signed token string itself is only ever
// kept in checkout_tokens until GET /license clears it after showing it
// once. A jti is a random correlation id, not a secret, so retaining it
// after the token is shown is not a leak.
type mintedToken struct {
	Token string
	JTI   string
	Exp   int64
}

// issueToken mints a fresh signed token for email, expiring GracePeriod
// past periodEnd (or, when periodEnd is unknown, past a one-month default
// from now).
func (s *Server) issueToken(email string, periodEnd int64) (mintedToken, error) {
	now := s.now()
	exp := now.Add(defaultPeriod + GracePeriod)
	if periodEnd > 0 {
		exp = time.Unix(periodEnd, 0).Add(GracePeriod)
	}
	jti := newJTI()
	token, err := license.Sign(s.signingKey, license.Payload{
		Sub:  email,
		Plan: license.PlanPro,
		Iat:  now.Unix(),
		Exp:  exp.Unix(),
		JTI:  jti,
	})
	if err != nil {
		return mintedToken{}, err
	}
	return mintedToken{Token: token, JTI: jti, Exp: exp.Unix()}, nil
}

func newJTI() string {
	var b [16]byte
	// crypto/rand.Read never returns a short read without an error, and an
	// error here is unrecoverable process-wide (no entropy source) — a
	// license service cannot mint tokens at all in that state.
	if _, err := rand.Read(b[:]); err != nil {
		panic("server: reading random bytes for a token id: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
