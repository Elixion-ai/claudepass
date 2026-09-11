package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"claudepass/services/license/internal/store"
)

// Every HTML response this service returns to a browser must share the
// site's header, footer and disclaimer (CLA-32/33/34). These constants
// are the exact strings every assertion below checks for, so a change to
// the shared layout that drops one of them fails loudly here rather than
// only being noticed by eye.
const (
	wantHeaderClass = `class="arcade-header"`
	wantFooterClass = `class="arcade-footer"`
	wantDisclaimer  = "ClaudePass is an independent product and is not affiliated with, endorsed by, or sponsored by Anthropic or OpenAI. Claude and Claude Code are trademarks of Anthropic, PBC."
)

// assertOnBrand fails unless body carries the shared header, footer,
// verbatim disclaimer, and the given H1.
func assertOnBrand(t *testing.T, body, h1 string) {
	t.Helper()
	if !strings.Contains(body, wantHeaderClass) {
		t.Errorf("page missing the shared header: %s", body)
	}
	if !strings.Contains(body, wantFooterClass) {
		t.Errorf("page missing the shared footer: %s", body)
	}
	if !strings.Contains(body, wantDisclaimer) {
		t.Errorf("page missing the verbatim disclaimer: %s", body)
	}
	if !strings.Contains(body, "<h1>"+h1+"</h1>") {
		t.Errorf("page missing H1 %q: %s", h1, body)
	}
	if strings.Contains(body, "<script>") {
		t.Errorf("page has an inline <script>, which the production CSP (script-src 'self') blocks: %s", body)
	}
	if strings.Contains(body, "style=\"") {
		t.Errorf("page has an inline style attribute, which the production CSP blocks: %s", body)
	}
}

func assertContentType(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
}

func TestLicenseReadyPageIsOnBrandAndCarriesTheToken(t *testing.T) {
	srv, d := newTestServer(t)
	now := time.Now()
	renewsAt := now.Add(30 * 24 * time.Hour)
	if err := d.Store.IssueForCheckout(context.Background(), store.IssuedToken{
		EventID: "evt_ready", SessionID: "cs_ready", CustomerID: "cus_ready", Email: "ready@example.com",
		PeriodEnd: renewsAt.Unix(), Now: now.Unix(), Token: "the-ready-token", JTI: "jti_ready", Exp: now.Unix() + 1000,
	}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license?session_id=cs_ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	body := rec.Body.String()
	assertOnBrand(t, body, "YOUR LICENSE IS READY")
	if !strings.Contains(body, "cpass license activate the-ready-token") {
		t.Fatalf("page should show the exact activate command: %s", body)
	}
	if !strings.Contains(body, "This is shown once. Copy it now.") {
		t.Fatalf("page missing the copy-once warning: %s", body)
	}
	if !strings.Contains(body, `class="copy-btn"`) {
		t.Fatalf("page missing the copy button: %s", body)
	}
	if !strings.Contains(body, ">plan<") || !strings.Contains(body, "Pro, $9.99/month") {
		t.Fatalf("page missing the plan summary row: %s", body)
	}
	// The subscriber's email and renewal date are both known to the
	// handler (IssueForCheckout above recorded them on the customer row
	// TakeCheckoutToken joins against) — the "account" row and the plan's
	// renewal date must actually reach the page, not just be supported by
	// dead template code nobody's call site feeds.
	if !strings.Contains(body, ">account<") || !strings.Contains(body, "ready@example.com") {
		t.Fatalf("page missing the account row with the subscriber's email: %s", body)
	}
	if !strings.Contains(body, "renews "+renewsAt.UTC().Format("Jan 2, 2006")) {
		t.Fatalf("page missing the plan's renewal date: %s", body)
	}
}

func TestLicenseAlreadyShownPageIsOnBrandAndNeverCarriesTheToken(t *testing.T) {
	srv, d := newTestServer(t)
	now := time.Now()
	if err := d.Store.IssueForCheckout(context.Background(), store.IssuedToken{
		EventID: "evt_seen", SessionID: "cs_seen", CustomerID: "cus_seen", Email: "seen@example.com",
		Now: now.Unix(), Token: "never-again-token", JTI: "jti_seen", Exp: now.Unix() + 1000,
	}); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	// First view shows it; second must not.
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/license?session_id=cs_seen", nil))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license?session_id=cs_seen", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	body := rec.Body.String()
	assertOnBrand(t, body, "ALREADY SHOWN")
	if strings.Contains(body, "never-again-token") {
		t.Fatalf("already-shown page must never carry the token: %s", body)
	}
}

func TestLicensePendingPageIsOnBrandAndNeverUsesErrorLanguage(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license?session_id=cs_unknown_pending", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	body := rec.Body.String()
	assertOnBrand(t, body, "FINISHING SETUP…")
	lower := strings.ToLower(body)
	for _, bad := range []string{"error", "failed", "declined"} {
		if strings.Contains(lower, bad) {
			t.Fatalf("pending page must not use %q: %s", bad, body)
		}
	}
	if !strings.Contains(body, "/license?session_id=cs_unknown_pending") {
		t.Fatalf("pending page should link back to the same session for reload: %s", body)
	}
}

func TestLicenseInvalidPageIsOnBrand(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	assertOnBrand(t, rec.Body.String(), "SESSION NOT FOUND")
}

func TestLicensePageStoreFailureRendersInternalErrorPage(t *testing.T) {
	srv, d := newTestServer(t)
	if err := d.Store.Close(); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/license?session_id=cs_after_close", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	assertOnBrand(t, rec.Body.String(), "SOMETHING WENT WRONG")
}

func TestCheckoutFailedPageIsOnBrandAndHidesTheRealError(t *testing.T) {
	srv, d := newTestServer(t)
	d.Checkout.err = errNoSuchThing("stripe is down")

	req := httptest.NewRequest(http.MethodPost, "/checkout", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	body := rec.Body.String()
	assertOnBrand(t, body, "COULD NOT START CHECKOUT")
	if strings.Contains(body, "stripe is down") {
		t.Fatalf("checkout error page must never carry the underlying error: %s", body)
	}
}

type errNoSuchThing string

func (e errNoSuchThing) Error() string { return string(e) }

func TestReissueSentPageIsOnBrandAndNeverCarriesTheToken(t *testing.T) {
	srv, d := newTestServer(t)
	now := time.Now()
	if err := d.Store.IssueForCheckout(context.Background(), store.IssuedToken{
		EventID: "evt_sent", SessionID: "cs_sent", CustomerID: "cus_sent", Email: "sent@example.com",
		PeriodEnd: now.Add(20 * 24 * time.Hour).Unix(), Now: now.Unix(), Token: "irrelevant",
		JTI: "jti_sent", Exp: now.Unix() + 1000,
	}); err != nil {
		t.Fatal(err)
	}

	rec := postReissue(t, srv.Handler(), "sent@example.com")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	body := rec.Body.String()
	assertOnBrand(t, body, "CHECK YOUR EMAIL")

	sent, ok := d.Mailer.last()
	if !ok {
		t.Fatal("expected an email to have been sent")
	}
	token := extractToken(t, sent.Text)
	if strings.Contains(body, token) {
		t.Fatalf("the reissue confirmation page must never carry the token: %s", body)
	}
}

func TestReissueNotFoundPageIsOnBrand(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := postReissue(t, srv.Handler(), "nobody@example.com")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	assertOnBrand(t, rec.Body.String(), "NO SUBSCRIPTION FOUND")
}

func TestReissueInactivePageIsOnBrandAndSaysRefused(t *testing.T) {
	srv, d := newTestServer(t)
	now := time.Now()
	if err := d.Store.IssueForCheckout(context.Background(), store.IssuedToken{
		EventID: "evt_inact", SessionID: "cs_inact", CustomerID: "cus_inact", Email: "inactive@example.com",
		Now: now.Unix(), Token: "irrelevant", JTI: "jti_inact", Exp: now.Unix() + 1000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.Store.UpdateSubscription(context.Background(), "evt_inact_cancel", "cus_inact", "",
		store.StatusCanceled, 0, now.Unix()); err != nil {
		t.Fatal(err)
	}

	rec := postReissue(t, srv.Handler(), "inactive@example.com")
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	body := rec.Body.String()
	assertOnBrand(t, body, "SUBSCRIPTION NOT ACTIVE")
	if !strings.Contains(body, "refused") {
		t.Fatalf("inactive-subscription page should say the reissue was refused: %s", body)
	}
	if !strings.Contains(body, "3 days") {
		t.Fatalf("inactive-subscription page should name the grace period: %s", body)
	}
	if len(d.Mailer.sent) != 0 {
		t.Fatalf("no email should have been sent for a refused reissue")
	}
}

func TestReissueMissingEmailPageIsOnBrand(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := postReissue(t, srv.Handler(), "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	assertOnBrand(t, rec.Body.String(), "EMAIL REQUIRED")
}

func TestReissueMailFailedPageIsOnBrandAndHidesTheRealError(t *testing.T) {
	srv, d := newTestServer(t)
	now := time.Now()
	if err := d.Store.IssueForCheckout(context.Background(), store.IssuedToken{
		EventID: "evt_mailfail", SessionID: "cs_mailfail", CustomerID: "cus_mailfail", Email: "mailfail@example.com",
		PeriodEnd: now.Add(20 * 24 * time.Hour).Unix(), Now: now.Unix(), Token: "irrelevant",
		JTI: "jti_mailfail", Exp: now.Unix() + 1000,
	}); err != nil {
		t.Fatal(err)
	}
	d.Mailer.err = errNoSuchThing("smtp: connection refused by mail.example.test")

	rec := postReissue(t, srv.Handler(), "mailfail@example.com")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	body := rec.Body.String()
	assertOnBrand(t, body, "COULD NOT SEND THE EMAIL")
	if strings.Contains(body, "smtp: connection refused") {
		t.Fatalf("mail-failed page must never carry the underlying error: %s", body)
	}
}

// TestReissueRefusesWhenMailerNotConfigured (reissue_test.go) already
// covers the NoopMailer path at the status-code level; this asserts the
// body it renders is the same on-brand page as a real send failure.
func TestReissueUnconfiguredMailerRendersOnBrandFailurePage(t *testing.T) {
	_, d := newTestServer(t)
	now := time.Now()
	if err := d.Store.IssueForCheckout(context.Background(), store.IssuedToken{
		EventID: "evt_nomailer2", SessionID: "cs_nomailer2", CustomerID: "cus_nomailer2", Email: "nomailer2@example.com",
		PeriodEnd: now.Add(20 * 24 * time.Hour).Unix(), Now: now.Unix(), Token: "irrelevant",
		JTI: "jti_nomailer2", Exp: now.Unix() + 1000,
	}); err != nil {
		t.Fatal(err)
	}
	srv2 := New(Deps{
		Store:      d.Store,
		Checkout:   d.Checkout,
		Portal:     d.Portal,
		SigningKey: d.SignKey,
		BaseURL:    "https://license.example.test",
	})
	rec := postReissue(t, srv2.Handler(), "nomailer2@example.com")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body)
	}
	assertOnBrand(t, rec.Body.String(), "COULD NOT SEND THE EMAIL")
}

func TestReissueStoreFailureRendersInternalErrorPage(t *testing.T) {
	srv, d := newTestServer(t)
	if err := d.Store.Close(); err != nil {
		t.Fatal(err)
	}
	rec := postReissue(t, srv.Handler(), "whoever@example.com")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body)
	}
	assertContentType(t, rec)
	assertOnBrand(t, rec.Body.String(), "SOMETHING WENT WRONG")
}
