package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"claudepass/services/license/internal/mailer"
	"claudepass/services/license/internal/store"
)

func postReissue(t *testing.T, h http.Handler, email string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/reissue", strings.NewReader("email="+email))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestReissueMissingEmail(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := postReissue(t, srv.Handler(), "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestReissueUnknownEmail(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := postReissue(t, srv.Handler(), "nobody@example.com")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusNotFound, rec.Body)
	}
}

func TestReissueActiveCustomerSendsTokenAndPortalLink(t *testing.T) {
	srv, d := newTestServer(t)
	now := time.Now()
	err := d.Store.IssueForCheckout(context.Background(), store.IssuedToken{
		EventID: "evt_r1", SessionID: "cs_r1", CustomerID: "cus_r1", Email: "active@example.com",
		PeriodEnd: now.Add(20 * 24 * time.Hour).Unix(), Now: now.Unix(), Token: "shown-already",
		JTI: "jti_r1", Exp: now.Unix() + 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Consume the checkout token, as GET /license normally would, so this
	// test exercises the independent /reissue path rather than piggybacking
	// on the checkout flow's stored token.
	if _, err := d.Store.TakeCheckoutToken(context.Background(), "cs_r1"); err != nil {
		t.Fatal(err)
	}
	d.Portal.url = "https://billing.stripe.test/p/cus_r1"

	rec := postReissue(t, srv.Handler(), "active@example.com")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "cpass license activate") {
		t.Fatalf("the HTTP response must never carry the token, only the email does: %s", rec.Body.String())
	}

	sent, ok := d.Mailer.last()
	if !ok {
		t.Fatal("expected an email to have been sent")
	}
	if sent.To != "active@example.com" {
		t.Fatalf("sent to %q, want active@example.com", sent.To)
	}
	if !strings.Contains(sent.Text, "cpass license activate ") {
		t.Fatalf("email body should carry the activate command: %s", sent.Text)
	}
	if !strings.Contains(sent.Text, d.Portal.url) {
		t.Fatalf("email body should carry the customer portal link: %s", sent.Text)
	}
	token := extractToken(t, sent.Text)
	verifyWithKey(t, token, d.PubKey)
}

func TestReissueRefusesWhenMailerNotConfigured(t *testing.T) {
	_, d := newTestServer(t)
	now := time.Now()
	err := d.Store.IssueForCheckout(context.Background(), store.IssuedToken{
		EventID: "evt_r2", SessionID: "cs_r2", CustomerID: "cus_r2", Email: "nomailer@example.com",
		PeriodEnd: now.Add(20 * 24 * time.Hour).Unix(), Now: now.Unix(), Token: "tok",
		JTI: "jti_r2", Exp: now.Unix() + 1000,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Rebuild the server with the real "not configured" mailer instead of
	// the recording fake, to prove the refusal path main.go actually wires
	// when LICENSE_SMTP_* is unset.
	srv2 := New(Deps{
		Store:      d.Store,
		Checkout:   d.Checkout,
		Portal:     d.Portal,
		Mailer:     mailer.NoopMailer{},
		SigningKey: d.SignKey,
		BaseURL:    "https://license.example.test",
	})

	rec := postReissue(t, srv2.Handler(), "nomailer@example.com")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusInternalServerError, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "cpass license activate") {
		t.Fatalf("a token must never appear in the response even when delivery fails: %s", rec.Body.String())
	}
}

func TestReissueOnlyAcceptsPost(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/reissue", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
