// Command render-pages writes one static HTML file per state
// services/license/internal/pages can render, plus the plain-text and
// HTML bodies services/license/internal/mailer builds for the /reissue
// email — a fixture set a designer or reviewer can open directly in a
// browser without running the license service at all (CLA-32/33/34
// design capture).
//
// It is deliberately kept out of cmd/cpass's build graph, the same
// hygiene services/license/cmd/mint follows and internal/e2e asserts for
// that tool: cpass only ever verifies license tokens, nothing under
// services/license/cmd is imported by, or shares a binary with, cmd/cpass.
//
// Usage:
//
//	go run ./services/license/cmd/render-pages -out <dir>
package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"claudepass/services/license/internal/mailer"
	"claudepass/services/license/internal/pages"
)

// exampleToken is deliberately unrealistic (it doesn't parse as a real
// license.Sign token) so nobody mistakes a fixture file for a live one.
const exampleToken = "cp1.EXAMPLE-TOKEN-DO-NOT-USE"

const examplePortalURL = "https://billing.stripe.test/p/cus_example"

const exampleEmail = "reviewer@example.com"

// exampleRenewsAt is a fixed date, not time.Now()-derived, so the
// license-ready fixture's plan summary is identical byte-for-byte on
// every run — a design reviewer diffing this file across two renders
// should see no unrelated churn from the clock.
var exampleRenewsAt = time.Date(2026, time.November, 11, 0, 0, 0, 0, time.UTC).Unix()

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr *os.File) int {
	fs := flag.NewFlagSet("render-pages", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "directory to write the fixture files into (created if missing)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *out == "" {
		_, _ = fmt.Fprintln(stderr, "render-pages: -out is required") // best-effort: nothing left to do with a broken stderr write
		return 2
	}

	if err := Render(*out); err != nil {
		_, _ = fmt.Fprintln(stderr, "render-pages:", err) // best-effort: nothing left to do with a broken stderr write
		return 1
	}
	return 0
}

// Render writes every fixture file into dir, creating it if needed.
// Exported so services/license/cmd/render-pages's own test can drive it
// directly, the same pattern services/license/cmd/mint's tests use for
// its run function.
func Render(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	htmlPages := []struct {
		file   string
		render func(http.ResponseWriter)
	}{
		{"license-ready.html", func(w http.ResponseWriter) { pages.LicenseReady(w, exampleToken, exampleEmail, exampleRenewsAt) }},
		{"license-already-shown.html", pages.LicenseAlreadyShown},
		{"license-pending.html", func(w http.ResponseWriter) { pages.LicensePending(w, "cs_example_session") }},
		{"license-invalid.html", pages.LicenseInvalid},
		{"checkout-error.html", pages.CheckoutFailed},
		{"reissue-sent.html", pages.ReissueSent},
		{"reissue-not-found.html", pages.ReissueNotFound},
		{"reissue-inactive.html", func(w http.ResponseWriter) { pages.ReissueInactive(w, 3) }},
		{"reissue-missing-email.html", pages.ReissueMissingEmail},
		{"reissue-mail-failed.html", pages.ReissueMailFailed},
		{"internal-error.html", pages.InternalError},
	}

	for _, p := range htmlPages {
		rec := newRecorder()
		p.render(rec)
		if err := os.WriteFile(filepath.Join(dir, p.file), rec.body.Bytes(), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", p.file, err)
		}
	}

	text, html := mailer.ReissueEmail(exampleToken, examplePortalURL)
	if err := os.WriteFile(filepath.Join(dir, "email-plain.txt"), []byte(text), 0o644); err != nil {
		return fmt.Errorf("write email-plain.txt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "email-html.html"), []byte(html), 0o644); err != nil {
		return fmt.Errorf("write email-html.html: %w", err)
	}

	return nil
}

// recorder is a minimal http.ResponseWriter that only ever needs to
// capture a body — render-pages has no real HTTP request to answer, so
// pulling in net/http/httptest for this one binary would be a test-only
// dependency shipped where it's not needed.
type recorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newRecorder() *recorder { return &recorder{header: make(http.Header), status: http.StatusOK} }

func (r *recorder) Header() http.Header         { return r.header }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) WriteHeader(status int)      { r.status = status }
