// Package mailer sends the /reissue email. It never logs a message body:
// SMTPMailer hands the body straight to net/smtp and logs only the
// recipient and a byte count, on failure.
package mailer

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

// Mailer sends one email as a plain-text body with an optional HTML
// alternative. Implementations must not log either.
type Mailer interface {
	Send(ctx context.Context, to, subject, text, html string) error
}

// ErrNotConfigured is returned by a NoopMailer: /reissue turns this into a
// refusal rather than silently discarding the token.
var ErrNotConfigured = errors.New("mailer: SMTP is not configured")

// NoopMailer is used when no SMTP settings are present. It never sends and
// never logs the message it was asked to send.
type NoopMailer struct{}

func (NoopMailer) Send(ctx context.Context, to, subject, text, html string) error {
	return ErrNotConfigured
}

// SMTPMailer sends mail over SMTP with STARTTLS, authenticating with
// PLAIN auth. It is the real implementation main.go wires when
// Config.MailerConfigured() is true.
type SMTPMailer struct {
	Host, Port, Username, Password, From string
}

// Send delivers one email. The context is not passed to net/smtp (the
// standard library client has no context-aware dial), so a slow mail
// server blocks this call; the caller's own request timeout bounds it.
func (m SMTPMailer) Send(_ context.Context, to, subject, text, html string) error {
	addr := net.JoinHostPort(m.Host, m.Port)
	auth := smtp.PlainAuth("", m.Username, m.Password, m.Host)

	msg := BuildMessage(m.From, to, subject, text, html)

	if m.Port == "465" {
		return m.sendTLS(addr, auth, to, msg)
	}
	if err := smtp.SendMail(addr, auth, m.From, []string{to}, msg); err != nil {
		return fmt.Errorf("mailer: send to %s: %w", to, err)
	}
	return nil
}

func (m SMTPMailer) sendTLS(addr string, auth smtp.Auth, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: m.Host})
	if err != nil {
		return fmt.Errorf("mailer: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }() // best-effort: c.Quit() below is the real session shutdown
	c, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		return fmt.Errorf("mailer: client %s: %w", addr, err)
	}
	defer func() { _ = c.Close() }() // best-effort: c.Quit() below is the real session shutdown
	if err := c.Auth(auth); err != nil {
		return fmt.Errorf("mailer: auth: %w", err)
	}
	if err := c.Mail(m.From); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// BuildMessage renders a complete RFC 5322 message, headers plus body.
// When html is "" the body is a single text/plain part, exactly as this
// function behaved before it grew an HTML alternative. When html is
// non-empty the body is multipart/alternative with a text/plain part
// first (most clients prefer the last part that they can render, so
// text comes first and HTML second) and a text/html part second, joined
// by a random boundary that cannot collide with either part's own
// content by construction (MIME boundaries are matched at the start of a
// line, and this function's callers never put a raw "--" + boundary
// sequence in a part).
func BuildMessage(from, to, subject, text, html string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", stripCRLF(from))
	fmt.Fprintf(&b, "To: %s\r\n", stripCRLF(to))
	fmt.Fprintf(&b, "Subject: %s\r\n", stripCRLF(subject))
	b.WriteString("MIME-Version: 1.0\r\n")

	if html == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("\r\n")
		b.WriteString(text)
		return []byte(b.String())
	}

	boundary := newBoundary()
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary)
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(text)
	b.WriteString("\r\n\r\n")

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
	b.WriteString(html)
	b.WriteString("\r\n\r\n")

	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return []byte(b.String())
}

// stripCRLF removes CR and LF from a single-line header value. Header
// values here are server/Stripe-sourced (a configured From address, a
// customer email from the store, a literal Subject constant), not
// end-user form input, but a stray CR/LF in any of them would otherwise
// let a crafted value inject extra header lines or a forged body into the
// message BuildMessage assembles by straight string concatenation.
func stripCRLF(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// newBoundary returns a MIME boundary token unique enough that it will
// never appear inside a rendered email part by accident.
func newBoundary() string {
	var buf [12]byte
	// crypto/rand.Read never returns a short read without an error; an
	// error here would mean the process has no entropy source at all,
	// the same unrecoverable condition server.newJTI treats as fatal.
	if _, err := rand.Read(buf[:]); err != nil {
		panic("mailer: reading random bytes for a MIME boundary: " + err.Error())
	}
	return "claudepass-" + hex.EncodeToString(buf[:])
}

// Disclaimer is the verbatim non-affiliation line every ClaudePass
// surface — site and email alike — must carry unchanged. Duplicated here
// rather than imported from services/license/internal/pages so that
// package (which sits behind net/http) and this one (which does not)
// never need to depend on each other.
const Disclaimer = "ClaudePass is an independent product and is not affiliated with, endorsed by, or sponsored by Anthropic or OpenAI. Claude and Claude Code are trademarks of Anthropic, PBC."

// Reissue email colours mirror site/tokens.json (the committed, parity-
// tested export of the Figma Color/Primitives collections that
// internal/site/tokens_test.go checks site/retro.css against) — the same
// values site/retro.css's Color tokens resolve to on an inner page
// (light-bg/light-fg/light-theme-amber; the terminal block's dark
// bg-void/ember; the .cab-panel border and table-header text, both
// --color-border/--color-text-secondary), listed here as the CSS custom
// property each constant mirrors, duplicated because an email client
// cannot load an external stylesheet — these become inline styles
// instead. Go and CSS/JSON can't literally share a variable, so keep
// these in sync by hand if the named token's value ever changes in
// site/tokens.json or retro.css; every colour this function uses must be
// one of these named constants, never a raw hex literal, so a palette
// change only ever touches this block.
//
// emailCodeBg previously duplicated a value (#0d120d) that had drifted
// from retro.css's own terminal-block background; that rule now reads
// --bg-void directly (see site/retro.css's ".inner-page .content
// .terminal, pre" rule), so this mirrors --bg-void too rather than
// re-introducing the stale value. Likewise emailMuted now mirrors
// --color-text-secondary's Light value (light-fg), not the #6b5f52 value
// retro.css no longer uses.
const (
	emailBg       = "#f8f6f3" // --color-bg-canvas (Light) / --light-bg
	emailText     = "#14110d" // --color-text-primary (Light) / --light-fg
	emailAccent   = "#9a4a0c" // --color-accent (Light) / --light-theme-amber
	emailCodeBg   = "#0e0a06" // --bg-void
	emailCodeText = "#ff8a1f" // --ember
	emailBorder   = "#d9cfc2" // --color-border (Light) / --sand
	emailMuted    = "#14110d" // --color-text-secondary (Light) / --light-fg
	emailFontMono = "ui-monospace,Menlo,Consolas,monospace"
)

// htmlEscaper escapes the handful of characters that matter inside the
// plain HTML this package emits (an email address and an activation
// token, both of which are attacker-influenced only in the sense that a
// customer controls their own subscription email).
var htmlEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&#34;",
	"'", "&#39;",
)

func escapeHTML(s string) string { return htmlEscaper.Replace(s) }

// ReissueEmail renders the plain-text and HTML bodies for a /reissue
// email: why the recipient is receiving it, the literal
// "cpass license activate <token>" command, the Stripe customer-portal
// link when portalURL is non-empty, and the disclaimer. No images, no
// marketing banner — this is a transactional email, and the HTML part is
// deliberately restrained: a single ~600px-wide block of inline-styled
// markup, no table layout. It carries its own small brand header/footer
// (classed arcade-header/arcade-footer, styled with the same inline
// colours as the rest of this function) so the email reads as the same
// product as the site and the license-service pages, even though an
// email can't load /retro.css to pick up those classes' real rules.
func ReissueEmail(token, portalURL string) (text, html string) {
	var t strings.Builder
	t.WriteString("Your fresh ClaudePass license. Run this on the machine where you use ClaudePass:\n\n")
	fmt.Fprintf(&t, "    cpass license activate %s\n", token)
	if portalURL != "" {
		fmt.Fprintf(&t, "\nManage your subscription: %s\n", portalURL)
	}
	fmt.Fprintf(&t, "\n%s\n", Disclaimer)

	var h strings.Builder
	h.WriteString(`<!doctype html><html><body style="margin:0;padding:0;background:` + emailBg + `;">`)
	// A structured-data annotation, not an executable script: mail
	// clients (Gmail among them) strip <script type="text/javascript">
	// outright, and this deliberately isn't one — type="application/ld+json"
	// never runs, it only describes the message for clients that read
	// schema.org markup. Nothing in this package should ever ship a live
	// script into an email a customer's mail client renders.
	fmt.Fprintf(&h, `<script type="application/ld+json">{"@context":"https://schema.org","@type":"EmailMessage","description":"Your fresh ClaudePass license, ready to activate."}</script>`)
	fmt.Fprintf(&h, `<div style="max-width:600px;margin:0 auto;padding:24px;font-family:%s;color:%s;background:%s;">`,
		emailFontMono, emailText, emailBg)
	fmt.Fprintf(&h, `<div class="arcade-header" style="font-size:12px;letter-spacing:0.05em;color:%s;margin:0 0 20px;">CLAUDEPASS</div>`,
		emailAccent)
	h.WriteString(`<h1 style="font-size:18px;margin:0 0 12px;">Your fresh ClaudePass license</h1>`)
	h.WriteString(`<p style="font-size:14px;line-height:1.5;margin:0 0 16px;">` +
		`You're receiving this because a fresh license was requested for your ClaudePass subscription. ` +
		`Run this once, on the machine where you use ClaudePass:</p>`)
	fmt.Fprintf(&h, `<pre style="background:%s;color:%s;padding:14px 16px;margin:0 0 16px;overflow-x:auto;font-family:%s;font-size:13px;">cpass license activate %s</pre>`,
		emailCodeBg, emailCodeText, emailFontMono, escapeHTML(token))
	if portalURL != "" {
		fmt.Fprintf(&h, `<p style="font-size:14px;margin:0 0 16px;"><a href="%s" style="color:%s;">Manage your subscription</a></p>`,
			escapeHTML(portalURL), emailAccent)
	}
	fmt.Fprintf(&h, `<div class="arcade-footer" style="margin:24px 0 0;border-top:1px solid %s;padding-top:16px;">`+
		`<p style="font-size:12px;color:%s;margin:0;">%s</p></div>`, emailBorder, emailMuted, escapeHTML(Disclaimer))
	h.WriteString(`</div></body></html>`)

	return t.String(), h.String()
}
