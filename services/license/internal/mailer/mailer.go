// Package mailer sends the /reissue email. It never logs a message body:
// SMTPMailer hands the body straight to net/smtp and logs only the
// recipient and a byte count, on failure.
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

// Mailer sends one email. Implementations must not log body.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// ErrNotConfigured is returned by a NoopMailer: /reissue turns this into a
// refusal rather than silently discarding the token.
var ErrNotConfigured = errors.New("mailer: SMTP is not configured")

// NoopMailer is used when no SMTP settings are present. It never sends and
// never logs the message it was asked to send.
type NoopMailer struct{}

func (NoopMailer) Send(ctx context.Context, to, subject, body string) error {
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
func (m SMTPMailer) Send(_ context.Context, to, subject, body string) error {
	addr := net.JoinHostPort(m.Host, m.Port)
	auth := smtp.PlainAuth("", m.Username, m.Password, m.Host)

	msg := buildMessage(m.From, to, subject, body)

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
	defer conn.Close()
	c, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		return fmt.Errorf("mailer: client %s: %w", addr, err)
	}
	defer c.Close()
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

func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}
