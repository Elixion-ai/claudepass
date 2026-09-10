package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"claudepass/internal/license"
	"claudepass/services/license/internal/store"
)

// fakeCheckout is a CheckoutCreator that never touches the network: it
// records the last email it was asked to prefill and returns a canned URL,
// or the configured error.
type fakeCheckout struct {
	mu        sync.Mutex
	url       string
	err       error
	lastEmail string
}

func (f *fakeCheckout) NewCheckoutSession(_ context.Context, email string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastEmail = email
	if f.err != nil {
		return "", f.err
	}
	if f.url == "" {
		return "https://checkout.stripe.test/session/cs_test_1", nil
	}
	return f.url, nil
}

// fakePortal is a PortalCreator that never touches the network.
type fakePortal struct {
	url string
	err error
}

func (f *fakePortal) NewPortalSession(_ context.Context, customerID string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if f.url == "" {
		return "https://billing.stripe.test/session/" + customerID, nil
	}
	return f.url, nil
}

// fakeMailer records every message sent instead of delivering it, so a
// test can assert on the body without any message ever reaching a real
// log or network call.
type fakeMailer struct {
	mu   sync.Mutex
	sent []sentMail
	err  error
}

type sentMail struct {
	To, Subject, Body string
}

func (f *fakeMailer) Send(_ context.Context, to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sentMail{To: to, Subject: subject, Body: body})
	return nil
}

func (f *fakeMailer) last() (sentMail, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return sentMail{}, false
	}
	return f.sent[len(f.sent)-1], true
}

// testDeps bundles the fakes and the temp store a test builds a Server
// from, so assertions on the fakes stay easy to reach without threading
// extra return values through every helper.
type testDeps struct {
	Store    *store.Store
	Checkout *fakeCheckout
	Portal   *fakePortal
	Mailer   *fakeMailer
	SignKey  ed25519.PrivateKey
	PubKey   ed25519.PublicKey
	LogBuf   *lockedBuffer
	clock    *testClock
}

func newTestServer(t *testing.T) (*Server, *testDeps) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "license.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() }) // best-effort cleanup

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	d := &testDeps{
		Store:    st,
		Checkout: &fakeCheckout{},
		Portal:   &fakePortal{},
		Mailer:   &fakeMailer{},
		SignKey:  priv,
		PubKey:   pub,
		LogBuf:   newLockedBuffer(),
		clock:    &testClock{t: time.Now()},
	}

	log := slog.New(slog.NewTextHandler(d.LogBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srv := New(Deps{
		Store:             st,
		Checkout:          d.Checkout,
		Portal:            d.Portal,
		Mailer:            d.Mailer,
		SigningKey:        priv,
		WebhookSecret:     testWebhookSecret,
		BaseURL:           "https://license.example.test",
		Logger:            log,
		Now:               d.clock.Now,
		TokenPollInterval: 5 * time.Millisecond,
		TokenPollAttempts: 20, // 100ms total: fast, but enough for the race test's deliberate delay
	})
	return srv, d
}

const testWebhookSecret = "whsec_test_secret"

// testClock lets a test hold "now" fixed or move it, without depending on
// wall-clock timing for expiry assertions.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// lockedBuffer is an io.Writer safe for concurrent use, so the request
// logging middleware (which runs on the server's goroutine, concurrently
// with a test's own assertions in some races) never trips -race.
type lockedBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func newLockedBuffer() *lockedBuffer { return &lockedBuffer{} }

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

var _ io.Writer = (*lockedBuffer)(nil)

// verifyWithKey checks a token's signature against pub directly, instead
// of through license.Verify: that function checks against internal/
// license's embedded production key (or, under the e2e build tag only, an
// override read from CPASS_TEST_LICENSE_PUBKEY), and these package tests
// run untagged with a throwaway per-test keypair. The full loop through
// license.Verify as the built cpass binary actually calls it is what
// services/license/e2e_test.go exercises, with that env override.
func verifyWithKey(t *testing.T, token string, pub ed25519.PublicKey) license.Payload {
	t.Helper()
	part1, part2, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("malformed token: %q", token)
	}
	body, err := base64.RawURLEncoding.DecodeString(part1)
	if err != nil {
		t.Fatalf("token payload segment: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(part2)
	if err != nil {
		t.Fatalf("token signature segment: %v", err)
	}
	if !ed25519.Verify(pub, []byte(part1), sig) {
		t.Fatalf("token signature does not verify against the issuing key")
	}
	var p license.Payload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("token payload: %v", err)
	}
	return p
}
