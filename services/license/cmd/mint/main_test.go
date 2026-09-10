package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claudepass/internal/license"
	"claudepass/services/license/internal/config"
)

// devKeypair returns a throwaway Ed25519 keypair and the base64 encoding
// mint expects in LICENSE_SIGNING_KEY, the same encoding
// internal/license/cmd/keygen prints and services/license/internal/config
// parses.
func devKeypair(t *testing.T) (pub ed25519.PublicKey, priv ed25519.PrivateKey, privB64 string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, base64.StdEncoding.EncodeToString(priv)
}

// envMap builds a getenv func from a plain map, the shape run()'s tests
// pass instead of touching the real process environment.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// verifyToken checks tok against pub independently of internal/license's
// own trusted-key machinery (which is fixed to the embedded production
// key outside an e2e build): it re-implements exactly the wire format
// internal/license's package doc comment describes, so a passing check
// here proves mint's output is byte-for-byte what a real cpass build's
// license.Verify parses and checks, without needing this test to run
// under -tags e2e.
func verifyToken(t *testing.T, tok string, pub ed25519.PublicKey) license.Payload {
	t.Helper()
	part1, part2, ok := strings.Cut(tok, ".")
	if !ok {
		t.Fatalf("token has no '.' separator: %q", tok)
	}
	b64 := base64.RawURLEncoding
	body, err := b64.DecodeString(part1)
	if err != nil {
		t.Fatalf("decode payload segment: %v", err)
	}
	sig, err := b64.DecodeString(part2)
	if err != nil {
		t.Fatalf("decode signature segment: %v", err)
	}
	if !ed25519.Verify(pub, []byte(part1), sig) {
		t.Fatalf("signature does not verify against the minting key's public half")
	}
	var p license.Payload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	return p
}

func TestMintRequiresSub(t *testing.T) {
	_, _, privB64 := devKeypair(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--plan", "pro", "--days", "30"},
		envMap(map[string]string{config.EnvSigningKey: privB64}), &stdout, &stderr, time.Now)
	if code != exitUsage {
		t.Fatalf("code = %d, want %d; stderr=%s", code, exitUsage, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty on a usage error: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--sub") {
		t.Fatalf("stderr should mention --sub: %s", stderr.String())
	}
}

func TestMintRejectsUnknownPlan(t *testing.T) {
	_, _, privB64 := devKeypair(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--sub", "owner@example.com", "--plan", "enterprise", "--days", "30"},
		envMap(map[string]string{config.EnvSigningKey: privB64}), &stdout, &stderr, time.Now)
	if code != exitUsage {
		t.Fatalf("code = %d, want %d; stderr=%s", code, exitUsage, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("stdout should be empty on a usage error")
	}
	if !strings.Contains(stderr.String(), "enterprise") {
		t.Fatalf("stderr should name the rejected plan: %s", stderr.String())
	}
}

func TestMintRequiresPositiveDays(t *testing.T) {
	_, _, privB64 := devKeypair(t)
	for _, days := range []string{"0", "-5"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"--sub", "owner@example.com", "--days", days},
			envMap(map[string]string{config.EnvSigningKey: privB64}), &stdout, &stderr, time.Now)
		if code != exitUsage {
			t.Fatalf("--days %s: code = %d, want %d; stderr=%s", days, code, exitUsage, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("--days %s: stdout should be empty", days)
		}
	}
}

func TestMintRequiresSigningKeyEnv(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--sub", "owner@example.com", "--days", "30"},
		envMap(nil), &stdout, &stderr, time.Now)
	if code != exitError {
		t.Fatalf("code = %d, want %d; stderr=%s", code, exitError, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatal("stdout should be empty when the signing key is missing")
	}
	if !strings.Contains(stderr.String(), config.EnvSigningKey) {
		t.Fatalf("stderr should name %s: %s", config.EnvSigningKey, stderr.String())
	}
}

func TestMintRejectsMalformedSigningKey(t *testing.T) {
	cases := map[string]string{
		"not base64":   "not-valid-base64!!!",
		"wrong length": base64.StdEncoding.EncodeToString([]byte("too-short")),
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{"--sub", "owner@example.com", "--days", "30"},
				envMap(map[string]string{config.EnvSigningKey: val}), &stdout, &stderr, time.Now)
			if code != exitError {
				t.Fatalf("code = %d, want %d; stderr=%s", code, exitError, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatal("stdout should be empty on a malformed key")
			}
		})
	}
}

func TestMintSuccessTokenOnStdoutAuditFirst(t *testing.T) {
	pub, _, privB64 := devKeypair(t)
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"--sub", "owner@example.com", "--plan", "pro", "--days", "365"},
		envMap(map[string]string{config.EnvSigningKey: privB64, EnvAuditLog: auditPath}),
		&stdout, &stderr, fixedNow(now),
	)
	if code != exitOK {
		t.Fatalf("code = %d, want %d; stderr=%s", code, exitOK, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr should be empty on success: %s", stderr.String())
	}

	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout should contain exactly one line (the token), got %d: %q", len(lines), stdout.String())
	}
	token := lines[0]

	p := verifyToken(t, token, pub)
	if p.Sub != "owner@example.com" || p.Plan != license.PlanPro {
		t.Fatalf("payload = %+v, want sub/plan owner@example.com/pro", p)
	}
	wantExp := now.AddDate(0, 0, 365).Unix()
	if p.Exp != wantExp {
		t.Fatalf("exp = %d, want %d", p.Exp, wantExp)
	}
	if p.Iat != now.Unix() {
		t.Fatalf("iat = %d, want %d", p.Iat, now.Unix())
	}
	if p.JTI == "" {
		t.Fatal("jti should not be empty")
	}

	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	audit := string(auditBytes)
	if strings.Contains(audit, token) {
		t.Fatalf("audit log must never contain the token itself: %s", audit)
	}
	if strings.Contains(audit, privB64) {
		t.Fatalf("audit log must never contain the signing key: %s", audit)
	}
	var rec auditRecord
	if err := json.Unmarshal(bytes.TrimSpace(auditBytes), &rec); err != nil {
		t.Fatalf("audit line is not valid JSON: %v (%s)", err, audit)
	}
	if rec.Sub != p.Sub || rec.Plan != p.Plan || rec.JTI != p.JTI {
		t.Fatalf("audit record %+v does not match minted payload %+v", rec, p)
	}
	if rec.Time != now.Format(time.RFC3339) {
		t.Fatalf("audit time = %q, want %q", rec.Time, now.Format(time.RFC3339))
	}
	if rec.Exp != time.Unix(wantExp, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("audit exp = %q", rec.Exp)
	}
}

func TestMintAppendsMultipleAuditLines(t *testing.T) {
	_, _, privB64 := devKeypair(t)
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	env := envMap(map[string]string{config.EnvSigningKey: privB64, EnvAuditLog: auditPath})

	for _, sub := range []string{"one@example.com", "two@example.com"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"--sub", sub, "--days", "30"}, env, &stdout, &stderr, time.Now)
		if code != exitOK {
			t.Fatalf("mint for %s: code %d, stderr %s", sub, code, stderr.String())
		}
	}
	b, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 audit lines, got %d: %s", len(lines), b)
	}
	if !strings.Contains(lines[0], "one@example.com") || !strings.Contains(lines[1], "two@example.com") {
		t.Fatalf("audit lines out of order or missing subs: %s", b)
	}
}

func TestMintDefaultAuditPathIsCwdMintAuditLog(t *testing.T) {
	_, _, privB64 := devKeypair(t)
	t.Chdir(t.TempDir())

	var stdout, stderr bytes.Buffer
	code := run([]string{"--sub", "owner@example.com", "--days", "30"},
		envMap(map[string]string{config.EnvSigningKey: privB64}), &stdout, &stderr, time.Now)
	if code != exitOK {
		t.Fatalf("code = %d, want %d; stderr=%s", code, exitOK, stderr.String())
	}
	if _, err := os.Stat(defaultAuditPath); err != nil {
		t.Fatalf("expected %s to be created in the cwd: %v", defaultAuditPath, err)
	}
}

func TestMintAuditWriteFailureFailsClosedNoToken(t *testing.T) {
	_, _, privB64 := devKeypair(t)
	// A directory can never be opened O_WRONLY as a regular file, so this
	// deterministically fails the audit write.
	dirAsAuditPath := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := run([]string{"--sub", "owner@example.com", "--days", "30"},
		envMap(map[string]string{config.EnvSigningKey: privB64, EnvAuditLog: dirAsAuditPath}),
		&stdout, &stderr, time.Now)
	if code != exitError {
		t.Fatalf("code = %d, want %d; stderr=%s", code, exitError, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("no token should be printed when the audit line could not be written: %q", stdout.String())
	}
}

func TestMintFreePlanAllowed(t *testing.T) {
	pub, _, privB64 := devKeypair(t)
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	var stdout, stderr bytes.Buffer
	code := run([]string{"--sub", "tester@example.com", "--plan", license.PlanFree, "--days", "7"},
		envMap(map[string]string{config.EnvSigningKey: privB64, EnvAuditLog: auditPath}),
		&stdout, &stderr, time.Now)
	if code != exitOK {
		t.Fatalf("code = %d, want %d; stderr=%s", code, exitOK, stderr.String())
	}
	token := strings.TrimSpace(stdout.String())
	p := verifyToken(t, token, pub)
	if p.Plan != license.PlanFree {
		t.Fatalf("plan = %q, want %q", p.Plan, license.PlanFree)
	}
}

func TestMintHelpExitsCleanly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help"}, envMap(nil), &stdout, &stderr, time.Now)
	if code != exitOK {
		t.Fatalf("code = %d, want %d", code, exitOK)
	}
	if stdout.Len() != 0 {
		t.Fatalf("help output must not touch stdout: %q", stdout.String())
	}
}

func TestMintRejectsExtraArguments(t *testing.T) {
	_, _, privB64 := devKeypair(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"--sub", "owner@example.com", "--days", "30", "extra"},
		envMap(map[string]string{config.EnvSigningKey: privB64}), &stdout, &stderr, time.Now)
	if code != exitUsage {
		t.Fatalf("code = %d, want %d", code, exitUsage)
	}
	if stdout.Len() != 0 {
		t.Fatal("stdout should be empty on a usage error")
	}
}
