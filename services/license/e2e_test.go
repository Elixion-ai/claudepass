// This file is the CLA-15 acceptance test proper: it drives the license
// service's real HTTP handler with a recorded Stripe webhook fixture, then
// hands the token it issues to the actually-built cpass binary — the exact
// boundary described in CONTEXT.md and docs/PRD.md's Testing Decisions
// ("the seam is the binary"). Everything below it (internal/server,
// internal/store, ...) already has its own focused tests; this file only
// proves the pieces compose the way the acceptance bullets require.
package main_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claudepass/services/license/internal/mailer"
	"claudepass/services/license/internal/server"
	"claudepass/services/license/internal/store"
	"claudepass/services/license/internal/webhookfixture"
)

var (
	cpassBin     string
	cpassBinOnce = &onceErr{}
)

// onceErr runs a build exactly once for the whole test binary and remembers
// its outcome, the same pattern internal/e2e/harness_test.go uses for its
// own cpass build.
type onceErr struct {
	done bool
	err  error
}

func buildCpassE2E(t *testing.T) string {
	t.Helper()
	if !cpassBinOnce.done {
		dir, err := os.MkdirTemp("", "cpass-license-e2e")
		if err != nil {
			t.Fatal(err)
		}
		cpassBin = filepath.Join(dir, "cpass")
		cmd := exec.Command("go", "build", "-tags", "e2e", "-o", cpassBin, "claudepass/cmd/cpass")
		cmd.Stderr = os.Stderr
		cpassBinOnce.err = cmd.Run()
		cpassBinOnce.done = true
	}
	if cpassBinOnce.err != nil {
		t.Fatalf("build cpass: %v", cpassBinOnce.err)
	}
	return cpassBin
}

// testServer wires a real, in-process HTTP server (httptest.NewServer, a
// real listening socket) around server.Handler(), with a throwaway Ed25519
// keypair the built cpass binary will be told to trust via
// CPASS_TEST_LICENSE_PUBKEY — the same e2e-only override
// internal/e2e/license_test.go uses for CLA-14.
type testServer struct {
	*httptest.Server
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	webhookKey string
	logBuf     *syncBuf
	mail       *recordingMailer
}

type syncBuf struct {
	mu  chan struct{}
	buf bytes.Buffer
}

func newSyncBuf() *syncBuf {
	b := &syncBuf{mu: make(chan struct{}, 1)}
	b.mu <- struct{}{}
	return b
}

func (b *syncBuf) Write(p []byte) (int, error) {
	<-b.mu
	defer func() { b.mu <- struct{}{} }()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	<-b.mu
	defer func() { b.mu <- struct{}{} }()
	return b.buf.String()
}

type recordingMailer struct {
	mu   chan struct{}
	last string
}

func newRecordingMailer() *recordingMailer {
	m := &recordingMailer{mu: make(chan struct{}, 1)}
	m.mu <- struct{}{}
	return m
}

func (m *recordingMailer) Send(_ context.Context, to, subject, text, html string) error {
	<-m.mu
	defer func() { m.mu <- struct{}{} }()
	m.last = text
	return nil
}

// Last returns the most recently sent body under the same lock Send
// writes through, so reading it from a test goroutine after an HTTP
// round-trip is race-detector-clean rather than relying on the round-trip
// alone to order the memory access.
func (m *recordingMailer) Last() string {
	<-m.mu
	defer func() { m.mu <- struct{}{} }()
	return m.last
}

func newTestService(t *testing.T) *testServer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "license.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() }) // best-effort cleanup

	logBuf := newSyncBuf()
	mail := newRecordingMailer()

	srv := server.New(server.Deps{
		Store:             st,
		Mailer:            mail,
		SigningKey:        priv,
		WebhookSecret:     "whsec_e2e_test",
		BaseURL:           "http://will-be-overwritten.invalid",
		Logger:            slog.New(slog.NewTextHandler(logBuf, nil)),
		TokenPollInterval: 5 * time.Millisecond,
		TokenPollAttempts: 20,
	})
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	return &testServer{Server: hs, priv: priv, pub: pub, webhookKey: "whsec_e2e_test", logBuf: logBuf, mail: mail}
}

func (ts *testServer) postWebhook(t *testing.T, body []byte, at time.Time) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/webhook", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Stripe-Signature", webhookfixture.SignatureHeader(ts.webhookKey, body, at))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (ts *testServer) getLicensePage(t *testing.T, sessionID string) string {
	t.Helper()
	resp, err := http.Get(ts.URL + "/license?session_id=" + sessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }() // best-effort cleanup
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /license: status %d body %s", resp.StatusCode, b)
	}
	return string(b)
}

func extractActivateToken(t *testing.T, page string) string {
	t.Helper()
	const marker = "cpass license activate "
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no activate command found:\n%s", page)
	}
	rest := page[i+len(marker):]
	end := strings.IndexAny(rest, "<\n")
	if end < 0 {
		end = len(rest)
	}
	return strings.TrimSpace(rest[:end])
}

func runCpass(t *testing.T, bin, home, testPubKey string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "CPASS_HOME="+home, "CPASS_TEST_LICENSE_PUBKEY="+testPubKey)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run cpass %v: %v", args, err)
	}
	return out.String(), errb.String(), code
}

// TestCheckoutWebhookIssuesTokenCpassActivateAccepts is the CLA-15
// acceptance bullet, verbatim: "go test with recorded Stripe webhook
// fixtures issues a token that `cpass license activate` accepts."
func TestCheckoutWebhookIssuesTokenCpassActivateAccepts(t *testing.T) {
	bin := buildCpassE2E(t)
	ts := newTestService(t)
	now := time.Now()

	body, err := webhookfixture.Render(webhookfixture.CheckoutSessionCompleted, webhookfixture.Values{
		SessionID: "cs_e2e_1", CustomerID: "cus_e2e_1", Email: "subscriber@example.com", Created: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp := ts.postWebhook(t, body, now); resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook delivery: status %d", resp.StatusCode)
	}

	page := ts.getLicensePage(t, "cs_e2e_1")
	token := extractActivateToken(t, page)
	if token == "" {
		t.Fatal("no token extracted from the license page")
	}

	pubKeyEnv := base64.StdEncoding.EncodeToString(ts.pub)
	home := t.TempDir()
	stdout, stderr, code := runCpass(t, bin, home, pubKeyEnv, "license", "activate", token)
	if code != 0 {
		t.Fatalf("cpass license activate: exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "subscriber@example.com") || !strings.Contains(stdout, "plan pro") {
		t.Fatalf("activate stdout should confirm the account and plan: %s", stdout)
	}

	stdout, _, code = runCpass(t, bin, home, pubKeyEnv, "license", "status")
	if code != 0 || !strings.Contains(stdout, "plan: pro") {
		t.Fatalf("status after activation: exit %d stdout %s", code, stdout)
	}

	// The service must never have logged the token anywhere.
	if strings.Contains(ts.logBuf.String(), token) {
		t.Fatalf("token leaked into the service's own log:\n%s", ts.logBuf.String())
	}
}

// TestReleaseCpassRefusesE2EIssuedToken is the mirror of
// internal/e2e's TestReleaseBinaryIgnoresLicenseTestPubkey, at this
// boundary: a token minted with a throwaway dev key must NOT verify
// against a real release build, which trusts only the production key
// embedded in internal/license/publickey.go. This is what makes the dev
// keypair here safe to generate per test run instead of the real
// production private key (which this Agent was never given — see
// services/license/README.md's NEEDS-HUMAN section).
func TestReleaseCpassRefusesE2EIssuedToken(t *testing.T) {
	dir, err := os.MkdirTemp("", "cpass-license-e2e-release")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) // best-effort cleanup
	releaseBin := filepath.Join(dir, "cpass-release")
	cmd := exec.Command("go", "build", "-o", releaseBin, "claudepass/cmd/cpass")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build release cpass: %v", err)
	}

	ts := newTestService(t)
	now := time.Now()
	body, err := webhookfixture.Render(webhookfixture.CheckoutSessionCompleted, webhookfixture.Values{
		SessionID: "cs_e2e_release", CustomerID: "cus_e2e_release", Email: "s2@example.com", Created: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts.postWebhook(t, body, now)
	token := extractActivateToken(t, ts.getLicensePage(t, "cs_e2e_release"))

	home := t.TempDir()
	cmdRun := exec.Command(releaseBin, "license", "activate", token)
	cmdRun.Env = append(os.Environ(), "CPASS_HOME="+home,
		"CPASS_TEST_LICENSE_PUBKEY="+base64.StdEncoding.EncodeToString(ts.pub))
	var out, errb bytes.Buffer
	cmdRun.Stdout, cmdRun.Stderr = &out, &errb
	err = cmdRun.Run()
	if err == nil {
		t.Fatal("a release binary must refuse a token signed with a non-production key")
	}
	if !strings.Contains(errb.String(), "refused") {
		t.Fatalf("release binary stderr should say refused: %s", errb.String())
	}
}

// TestSubscriptionCanceledThenReissueRefusedOverHTTP repeats the CLA-15
// "subscription deleted -> next reissue refused" acceptance bullet against
// the real listening HTTP server (internal/server has the same assertion
// against the handler directly; this closes the loop over an actual
// socket, matching how Stripe and a browser would really reach this
// service).
func TestSubscriptionCanceledThenReissueRefusedOverHTTP(t *testing.T) {
	ts := newTestService(t)
	now := time.Now()

	completed, err := webhookfixture.Render(webhookfixture.CheckoutSessionCompleted, webhookfixture.Values{
		SessionID: "cs_e2e_cancel", CustomerID: "cus_e2e_cancel", SubscriptionID: "sub_e2e_cancel",
		Email: "cancels@example.com", Created: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts.postWebhook(t, completed, now)
	ts.getLicensePage(t, "cs_e2e_cancel") // consume the first token, as the browser would

	deleted, err := webhookfixture.Render(webhookfixture.SubscriptionDeleted, webhookfixture.Values{
		SubscriptionID: "sub_e2e_cancel", CustomerID: "cus_e2e_cancel", Created: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp := ts.postWebhook(t, deleted, now); resp.StatusCode != http.StatusOK {
		t.Fatalf("subscription.deleted webhook: status %d", resp.StatusCode)
	}

	resp, err := http.PostForm(ts.URL+"/reissue", map[string][]string{"email": {"cancels@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }() // best-effort cleanup
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("reissue after cancellation: status %d body %s", resp.StatusCode, b)
	}
	if !strings.Contains(string(b), "refused") {
		t.Fatalf("refusal body should say so: %s", b)
	}
	if ts.mail.Last() != "" {
		t.Fatalf("no email should have been sent for a refused reissue")
	}
}

var _ mailer.Mailer = (*recordingMailer)(nil)
