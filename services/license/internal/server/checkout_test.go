package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckoutRedirectsToStripe(t *testing.T) {
	srv, d := newTestServer(t)
	d.Checkout.url = "https://checkout.stripe.test/session/cs_abc"

	req := httptest.NewRequest(http.MethodPost, "/checkout?email=dev%40example.com", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != d.Checkout.url {
		t.Fatalf("Location = %q, want %q", loc, d.Checkout.url)
	}
	if d.Checkout.lastEmail != "dev@example.com" {
		t.Fatalf("checkout session should have been created with the prefilled email, got %q", d.Checkout.lastEmail)
	}
}

func TestCheckoutWithoutEmailStillWorks(t *testing.T) {
	srv, d := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/checkout", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if d.Checkout.lastEmail != "" {
		t.Fatalf("no email was given, want empty prefill, got %q", d.Checkout.lastEmail)
	}
}

func TestCheckoutSurfacesStripeFailure(t *testing.T) {
	srv, d := newTestServer(t)
	d.Checkout.err = errors.New("stripe is down")

	req := httptest.NewRequest(http.MethodPost, "/checkout", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if strings.Contains(rec.Body.String(), "stripe is down") {
		t.Fatalf("internal Stripe error detail should not reach the client: %s", rec.Body.String())
	}
}

func TestCheckoutOnlyAcceptsPost(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/checkout", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /checkout: status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}
