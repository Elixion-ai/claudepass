package server

import (
	"net/http"
)

// handleCheckout creates a Stripe Checkout Session for the $9.99/month
// price and redirects the browser to it. An optional "email" form value
// (query string or POST body) prefills the Checkout form.
func (s *Server) handleCheckout(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")

	url, err := s.checkout.NewCheckoutSession(r.Context(), email)
	if err != nil {
		s.log.Error("create checkout session", "error", err)
		http.Error(w, "could not start checkout", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, url, http.StatusSeeOther)
}
