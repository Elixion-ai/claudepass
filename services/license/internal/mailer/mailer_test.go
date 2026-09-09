package mailer

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNoopMailerRefuses(t *testing.T) {
	var m Mailer = NoopMailer{}
	err := m.Send(context.Background(), "a@example.com", "subject", "cpass license activate super-secret-token")
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestBuildMessageNeverTruncatesBodyAndSetsHeaders(t *testing.T) {
	msg := string(buildMessage("license@example.test", "user@example.com", "Your license", "cpass license activate tok.sig\n"))
	for _, want := range []string{
		"From: license@example.test",
		"To: user@example.com",
		"Subject: Your license",
		"cpass license activate tok.sig",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q:\n%s", want, msg)
		}
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
