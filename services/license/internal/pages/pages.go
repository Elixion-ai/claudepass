// Package pages renders every HTML response the license service returns
// to a browser through one shared layout (services/license/internal/pages
// /templates/layout.html): the same header nav, footer, verbatim
// non-affiliation disclaimer and stylesheet as the static site under
// site/, so a page this service serves is indistinguishable from one
// Caddy serves directly (CLA-32/33/34).
//
// Every render func here writes Content-Type: text/html; charset=utf-8,
// sets the exact status code its caller asks for, and never logs a
// token — the templates receive one and print it into the page body,
// which is the one sanctioned place a token may appear (license_ready.html
// only). See services/license/internal/server's package doc comment for
// the token-never-logged invariant this package must not break.
package pages

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

// SupportEmail is the one place an error page's "contact us" line reads
// from. It is a placeholder the repo owner must confirm before this
// service takes real traffic (services/license/README.md's NEEDS-HUMAN
// pattern) — change it here and every page picks it up.
const SupportEmail = "support@claudepass.com"

var funcs = template.FuncMap{
	"supportEmail": func() string { return SupportEmail },
}

// layout is the shared shell, parsed once. Each page below is its own
// clone of layout with exactly one page's "title"/"description"/"content"
// definitions parsed in — cloning first means two pages can each define a
// block named "content" without colliding with each other, which parsing
// every template file into one shared *template.Template would not allow.
var layout = template.Must(template.New("layout").Funcs(funcs).ParseFS(templateFS, "templates/layout.html"))

func page(file string) *template.Template {
	t := template.Must(layout.Clone())
	return template.Must(t.ParseFS(templateFS, "templates/"+file))
}

var (
	tmplLicenseReady        = page("license_ready.html")
	tmplLicenseAlreadyShown = page("license_already_shown.html")
	tmplLicensePending      = page("license_pending.html")
	tmplLicenseInvalid      = page("license_invalid.html")
	tmplCheckoutFailed      = page("checkout_failed.html")
	tmplReissueSent         = page("reissue_sent.html")
	tmplReissueNotFound     = page("reissue_not_found.html")
	tmplReissueInactive     = page("reissue_inactive.html")
	tmplReissueMissingEmail = page("reissue_missing_email.html")
	tmplReissueMailFailed   = page("reissue_mail_failed.html")
	tmplInternalError       = page("internal_error.html")
)

// render executes tmpl into a buffer first, so a template error can never
// leave a response half-written under the wrong status code, then writes
// the buffer as the one and only response write.
func render(w http.ResponseWriter, tmpl *template.Template, status int, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		// Every template here is a package-embedded constant parsed at
		// init; a failure means this package itself is broken, not
		// anything about the request. There is no page left to render
		// through, so this is the one spot a bare http.Error is correct.
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w) // best-effort: nothing left to do with a broken response write
}

// licenseReadyData feeds license_ready.html. Token is rendered inside a
// <code> element, where html/template's contextual autoescaping is
// exactly the HTML-escaping the token needs (its own alphabet — base64url
// plus one '.' — needs none, but nothing here depends on that being
// true). Email is optional: the "account" row is omitted when the
// handler does not know it. RenewsOn is a pre-formatted date string,
// already empty when the handler has no period-end to show — formatting
// happens once here rather than in the template so the template never
// has to reason about a zero time.Time or a bare unix timestamp.
type licenseReadyData struct {
	Token    string
	Email    string
	RenewsOn string
}

// formatRenewsOn turns a unix-seconds period end into the date string
// license_ready.html's plan summary shows ("renews Jan 2, 2006"), or ""
// when periodEnd is unknown (0) so the template omits the clause.
func formatRenewsOn(periodEnd int64) string {
	if periodEnd <= 0 {
		return ""
	}
	return time.Unix(periodEnd, 0).UTC().Format("Jan 2, 2006")
}

// LicenseReady renders the CLA-32 "Success — Token Ready" state (200):
// the exact `cpass license activate <token>` command with a copy button,
// a copy-once warning, and the plan/account summary. email may be "" when
// the handler has no subscriber email to show; periodEnd may be 0 when
// the handler has no renewal date to show (both omit their row/clause
// rather than printing a blank).
func LicenseReady(w http.ResponseWriter, token, email string, periodEnd int64) {
	render(w, tmplLicenseReady, http.StatusOK, licenseReadyData{
		Token:    token,
		Email:    email,
		RenewsOn: formatRenewsOn(periodEnd),
	})
}

// LicenseAlreadyShown renders the CLA-32 "Revisited/Already Shown" state.
// Still 200: the request succeeded, it just has nothing new to show.
func LicenseAlreadyShown(w http.ResponseWriter) {
	render(w, tmplLicenseAlreadyShown, http.StatusOK, nil)
}

type licensePendingData struct {
	SessionID string
}

// LicensePending renders the CLA-32 "Pending" state (404, per the
// service's existing contract: the checkout session isn't found *yet*).
// sessionID is carried into the reload link so the visitor doesn't have
// to find the URL again; html/template escapes it for the href context.
func LicensePending(w http.ResponseWriter, sessionID string) {
	render(w, tmplLicensePending, http.StatusNotFound, licensePendingData{SessionID: sessionID})
}

// LicenseInvalid renders the CLA-32 "Invalid/Expired Session" state
// (400): GET /license with no session_id at all.
func LicenseInvalid(w http.ResponseWriter) {
	render(w, tmplLicenseInvalid, http.StatusBadRequest, nil)
}

// CheckoutFailed renders the CLA-32 "Checkout — Error" state (502): Stripe
// Checkout session creation failed. Never carries the underlying error.
func CheckoutFailed(w http.ResponseWriter) {
	render(w, tmplCheckoutFailed, http.StatusBadGateway, nil)
}

// ReissueSent renders the CLA-33 "Confirmation Sent" state (200). The
// token itself never reaches this page — only the email does.
func ReissueSent(w http.ResponseWriter) {
	render(w, tmplReissueSent, http.StatusOK, nil)
}

// ReissueNotFound renders the CLA-33 "No Subscription Found" state (404).
func ReissueNotFound(w http.ResponseWriter) {
	render(w, tmplReissueNotFound, http.StatusNotFound, nil)
}

type reissueInactiveData struct {
	GraceDays int
}

// ReissueInactive renders the CLA-33 "Subscription Not Active" state
// (402): a canceled subscription's reissue is refused. graceDays is
// server.GracePeriod expressed in whole days, so this package does not
// need to import server (which imports this package) to know it.
func ReissueInactive(w http.ResponseWriter, graceDays int) {
	render(w, tmplReissueInactive, http.StatusPaymentRequired, reissueInactiveData{GraceDays: graceDays})
}

// ReissueMissingEmail renders the CLA-33 "Missing Email" state (400).
func ReissueMissingEmail(w http.ResponseWriter) {
	render(w, tmplReissueMissingEmail, http.StatusBadRequest, nil)
}

// ReissueMailFailed renders the CLA-33 "Could Not Send" state (500),
// covering both a real send failure and the mailer being unconfigured.
func ReissueMailFailed(w http.ResponseWriter) {
	render(w, tmplReissueMailFailed, http.StatusInternalServerError, nil)
}

// InternalError renders the CLA-34 generic 500 state for every handler
// path that hits an error it cannot attribute to the visitor (a store
// failure, a signing failure, ...). Never carries internals.
func InternalError(w http.ResponseWriter) {
	render(w, tmplInternalError, http.StatusInternalServerError, nil)
}
