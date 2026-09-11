package mailer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNoopMailerRefuses(t *testing.T) {
	var m Mailer = NoopMailer{}
	err := m.Send(context.Background(), "a@example.com", "subject",
		"cpass license activate super-secret-token", "<p>cpass license activate super-secret-token</p>")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestBuildMessagePlainOnlyNeverTruncatesBodyAndSetsHeaders(t *testing.T) {
	msg := string(BuildMessage("license@example.test", "user@example.com", "Your license", "cpass license activate tok.sig\n", ""))
	for _, want := range []string{
		"From: license@example.test",
		"To: user@example.com",
		"Subject: Your license",
		"cpass license activate tok.sig",
		"Content-Type: text/plain; charset=UTF-8",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "multipart") {
		t.Fatalf("an empty html part should produce a plain text/plain message, not multipart:\n%s", msg)
	}
	headers, body, ok := strings.Cut(msg, "\r\n\r\n")
	if !ok {
		t.Fatalf("message should separate headers from body with a blank line:\n%s", msg)
	}
	if strings.Contains(headers, "cpass license activate") {
		t.Fatalf("the token must be in the body, not folded into a header:\n%s", msg)
	}
	if !strings.Contains(body, "cpass license activate tok.sig") {
		t.Fatalf("body missing the activate command:\n%s", body)
	}
}

func TestBuildMessageMultipartAlternative(t *testing.T) {
	text := "cpass license activate tok.sig\n"
	html := "<p>cpass license activate tok.sig</p>"
	msg := string(BuildMessage("license@example.test", "user@example.com", "Your license", text, html))

	if !strings.Contains(msg, "Content-Type: multipart/alternative; boundary=") {
		t.Fatalf("message should declare a multipart/alternative boundary:\n%s", msg)
	}
	if !strings.Contains(msg, "Content-Type: text/plain; charset=UTF-8") {
		t.Fatalf("message missing the text/plain part header:\n%s", msg)
	}
	if !strings.Contains(msg, "Content-Type: text/html; charset=UTF-8") {
		t.Fatalf("message missing the text/html part header:\n%s", msg)
	}
	if !strings.Contains(msg, text) {
		t.Fatalf("message missing the plain-text part body:\n%s", msg)
	}
	if !strings.Contains(msg, html) {
		t.Fatalf("message missing the html part body:\n%s", msg)
	}

	headers, _, ok := strings.Cut(msg, "\r\n\r\n")
	if !ok {
		t.Fatalf("message should separate headers from body with a blank line:\n%s", msg)
	}
	if strings.Contains(headers, "tok.sig") {
		t.Fatalf("the token must never appear in a header:\n%s", msg)
	}

	// The boundary line that opens each part must also close the message.
	i := strings.Index(msg, "boundary=\"")
	if i < 0 {
		t.Fatal("no boundary found")
	}
	rest := msg[i+len("boundary=\""):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		t.Fatal("unterminated boundary value")
	}
	boundary := rest[:end]
	if !strings.Contains(msg, "--"+boundary+"--") {
		t.Fatalf("message never closes boundary %q:\n%s", boundary, msg)
	}
}

func TestReissueEmailCarriesActivateCommandPortalAndDisclaimerInBothParts(t *testing.T) {
	text, html := ReissueEmail("tok.sig", "https://billing.stripe.test/p/cus_1")

	for _, part := range []string{text, html} {
		if !strings.Contains(part, "cpass license activate tok.sig") {
			t.Fatalf("part missing the activate command: %s", part)
		}
		if !strings.Contains(part, "https://billing.stripe.test/p/cus_1") {
			t.Fatalf("part missing the customer portal link: %s", part)
		}
		if !strings.Contains(part, Disclaimer) {
			t.Fatalf("part missing the verbatim disclaimer: %s", part)
		}
	}
	if !strings.Contains(html, "<pre") {
		t.Fatalf("html part should carry the command in a code block: %s", html)
	}
}

func TestReissueEmailOmitsPortalLinkWhenAbsent(t *testing.T) {
	text, html := ReissueEmail("tok.sig", "")
	if strings.Contains(text, "Manage your subscription") || strings.Contains(html, "Manage your subscription") {
		t.Fatalf("no portal link was given; neither part should mention managing the subscription:\ntext=%s\nhtml=%s", text, html)
	}
}

// TestReissueEmailHTMLCarriesBrandMarkersAndNoLiveScript locks in the
// email HTML's parity with the rest of the on-brand surfaces (the same
// arcade-header/arcade-footer class names as site/ and the license-service
// pages) while keeping the one <script> element inert: an
// application/ld+json annotation mail clients never execute, never a
// javascript one that fetches /js/site.js (email clients strip that kind
// outright, and CSP's script-src 'self' doesn't even apply to mail).
func TestReissueEmailHTMLCarriesBrandMarkersAndNoLiveScript(t *testing.T) {
	_, html := ReissueEmail("tok.sig", "https://billing.stripe.test/p/cus_1")

	if !strings.Contains(html, `class="arcade-header"`) {
		t.Fatalf("html part missing the shared arcade-header class: %s", html)
	}
	if !strings.Contains(html, `class="arcade-footer"`) {
		t.Fatalf("html part missing the shared arcade-footer class: %s", html)
	}
	if n := strings.Count(html, "<script"); n != 1 {
		t.Fatalf("html part has %d <script tags, want exactly 1: %s", n, html)
	}
	if !strings.Contains(html, `<script type="application/ld+json">`) {
		t.Fatalf("the one <script> tag must be an inert application/ld+json annotation, not executable JS: %s", html)
	}
}
