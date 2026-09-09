package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"claudepass/services/license/internal/webhookfixture"
)

func postWebhook(t *testing.T, h http.Handler, body []byte, at time.Time) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set("Stripe-Signature", webhookfixture.SignatureHeader(testWebhookSecret, body, at))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestCheckoutCompletedIssuesTokenCpassAccepts is the CLA-15 acceptance
// bullet at the handler level: a recorded checkout.session.completed
// fixture, once processed, must make GET /license hand back a token that
// verifies against the same public key the fixture's private key signs
// with (the full loop through the built cpass binary lives in
// services/license/e2e_test.go).
func TestCheckoutCompletedIssuesTokenCpassAccepts(t *testing.T) {
	srv, d := newTestServer(t)
	h := srv.Handler()

	now := time.Now()
	body, err := webhookfixture.Render(webhookfixture.CheckoutSessionCompleted, webhookfixture.Values{
		SessionID:  "cs_test_accept",
		CustomerID: "cus_test_accept",
		Email:      "dev@example.com",
		Created:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := postWebhook(t, h, body, now)
	if rec.Code != http.StatusOK {
		t.Fatalf("webhook: status %d body %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/license?session_id=cs_test_accept", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("license page: status %d body %s", rec.Code, rec.Body)
	}

	token := extractToken(t, rec.Body.String())
	verifyWithKey(t, token, d.PubKey)
	if !strings.Contains(rec.Body.String(), "cpass license activate "+token) {
		t.Fatalf("license page should show the exact activate command: %s", rec.Body.String())
	}

	// The service never logs a token: it appears only in this HTTP
	// response and in the store's now-cleared column, never in a log
	// line.
	if strings.Contains(d.LogBuf.String(), token) {
		t.Fatalf("token leaked into the service log: %s", d.LogBuf.String())
	}
}

func extractToken(t *testing.T, page string) string {
	t.Helper()
	const marker = "cpass license activate "
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no activate command in page: %s", page)
	}
	rest := page[i+len(marker):]
	end := strings.IndexAny(rest, "<\n")
	if end < 0 {
		end = len(rest)
	}
	return strings.TrimSpace(rest[:end])
}

func TestCheckoutCompletedUsesRealPeriodEndWhenSubscriptionExpanded(t *testing.T) {
	// The fixture's `subscription` field is a bare id (as Stripe sends it
	// unexpanded), so the token minted here should fall back to the
	// default period, not a zero expiry.
	srv, d := newTestServer(t)
	h := srv.Handler()
	now := time.Now()
	body, err := webhookfixture.Render(webhookfixture.CheckoutSessionCompleted, webhookfixture.Values{
		SessionID: "cs_test_default_period", CustomerID: "cus_x", Email: "a@example.com", Created: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec := postWebhook(t, h, body, now); rec.Code != http.StatusOK {
		t.Fatalf("webhook: %d %s", rec.Code, rec.Body)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license?session_id=cs_test_default_period", nil))
	token := extractToken(t, rec.Body.String())
	p := verifyWithKey(t, token, d.PubKey)
	wantMin := now.Add(30 * 24 * time.Hour).Unix()
	if p.Exp < wantMin {
		t.Fatalf("exp %d should be at least a month out, got less than %d", p.Exp, wantMin)
	}
}

func TestWebhookRejectsBadSignature(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()
	now := time.Now()
	body, _ := webhookfixture.Render(webhookfixture.CheckoutSessionCompleted, webhookfixture.Values{Created: now})

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set("Stripe-Signature", webhookfixture.SignatureHeader("wrong_secret", body, now))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad signature, got %d", rec.Code)
	}
}

func TestWebhookIdempotentOnDuplicateDelivery(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()
	now := time.Now()
	body, _ := webhookfixture.Render(webhookfixture.CheckoutSessionCompleted, webhookfixture.Values{
		EventID: "evt_dup_1", SessionID: "cs_dup", CustomerID: "cus_dup", Email: "dup@example.com", Created: now,
	})

	first := postWebhook(t, h, body, now)
	if first.Code != http.StatusOK {
		t.Fatalf("first delivery: %d %s", first.Code, first.Body)
	}
	// Take the token once, as GET /license would.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license?session_id=cs_dup", nil))
	firstToken := extractToken(t, rec.Body.String())

	// Stripe redelivers the identical event (e.g. after a slow 200 that
	// still looked like a timeout to Stripe). Processing must be a no-op:
	// it must not re-populate a cleared, already-shown token.
	second := postWebhook(t, h, body, now)
	if second.Code != http.StatusOK {
		t.Fatalf("duplicate delivery should still ack 200: %d %s", second.Code, second.Body)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/license?session_id=cs_dup", nil))
	if strings.Contains(rec2.Body.String(), firstToken) {
		t.Fatalf("duplicate webhook delivery re-exposed an already-shown token")
	}
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), "already") {
		t.Fatalf("second license page view should report already shown: %d %s", rec2.Code, rec2.Body.String())
	}
}

func TestSubscriptionDeletedThenReissueRefused(t *testing.T) {
	srv, d := newTestServer(t)
	h := srv.Handler()
	now := time.Now()

	// A customer completes checkout...
	completed, _ := webhookfixture.Render(webhookfixture.CheckoutSessionCompleted, webhookfixture.Values{
		SessionID: "cs_cancel_flow", CustomerID: "cus_cancel_flow", SubscriptionID: "sub_cancel_flow",
		Email: "cancels@example.com", Created: now,
	})
	if rec := postWebhook(t, h, completed, now); rec.Code != http.StatusOK {
		t.Fatalf("checkout webhook: %d %s", rec.Code, rec.Body)
	}

	// ...then cancels.
	deleted, _ := webhookfixture.Render(webhookfixture.SubscriptionDeleted, webhookfixture.Values{
		SubscriptionID: "sub_cancel_flow", CustomerID: "cus_cancel_flow", Created: now,
	})
	if rec := postWebhook(t, h, deleted, now); rec.Code != http.StatusOK {
		t.Fatalf("subscription.deleted webhook: %d %s", rec.Code, rec.Body)
	}

	// The next reissue for that email must be refused (CLA-15 acceptance).
	req := httptest.NewRequest(http.MethodPost, "/reissue", strings.NewReader("email=cancels@example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("reissue after cancellation: want %d, got %d: %s", http.StatusPaymentRequired, rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "refused") {
		t.Fatalf("refusal body should say so: %s", rec.Body.String())
	}
	if len(d.Mailer.sent) != 0 {
		t.Fatalf("no email should have been sent for a refused reissue")
	}
}

func TestSubscriptionUpdatedRefreshesPeriodEndForReissue(t *testing.T) {
	srv, d := newTestServer(t)
	h := srv.Handler()
	now := time.Now()

	completed, _ := webhookfixture.Render(webhookfixture.CheckoutSessionCompleted, webhookfixture.Values{
		SessionID: "cs_renew", CustomerID: "cus_renew", SubscriptionID: "sub_renew",
		Email: "renew@example.com", Created: now,
	})
	postWebhook(t, h, completed, now)

	renewedPeriodEnd := now.Add(60 * 24 * time.Hour)
	updated, _ := webhookfixture.Render(webhookfixture.SubscriptionUpdated, webhookfixture.Values{
		SubscriptionID: "sub_renew", CustomerID: "cus_renew", Created: now, PeriodEnd: renewedPeriodEnd,
	})
	if rec := postWebhook(t, h, updated, now); rec.Code != http.StatusOK {
		t.Fatalf("subscription.updated webhook: %d %s", rec.Code, rec.Body)
	}

	req := httptest.NewRequest(http.MethodPost, "/reissue", strings.NewReader("email=renew@example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reissue after renewal: %d %s", rec.Code, rec.Body)
	}

	sent, ok := d.Mailer.last()
	if !ok {
		t.Fatal("reissue should have sent an email")
	}
	token := extractToken(t, sent.Body)
	p := verifyWithKey(t, token, d.PubKey)
	wantExp := renewedPeriodEnd.Add(GracePeriod).Unix()
	if p.Exp != wantExp {
		t.Fatalf("reissued token exp = %d, want %d (renewed period end + grace)", p.Exp, wantExp)
	}
}

func TestWebhookIgnoresUnknownEventType(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()
	now := time.Now()
	body := []byte(`{"id":"evt_ignored","object":"event","api_version":"2025-01-01.preview","created":` +
		strconv.FormatInt(now.Unix(), 10) + `,"livemode":false,"pending_webhooks":1,"type":"invoice.paid","data":{"object":{}}}`)
	rec := postWebhook(t, h, body, now)
	if rec.Code != http.StatusOK {
		t.Fatalf("unknown event type should still ack 200, got %d: %s", rec.Code, rec.Body)
	}
}
