// Command mint is the owner-only tool for issuing ClaudePass license
// tokens outside Stripe Checkout — for the owner's own machines, testers,
// or support cases (CLA-43, follow-up from CLA-42's checkout/webhook
// path). It is the one sanctioned way to do that: no ad-hoc, undocumented
// tool should exist alongside it, so every owner-issued token leaves the
// same audit trail.
//
// It is deliberately kept out of cmd/cpass, in its own main package under
// services/license/cmd, next to the license service that holds the same
// signing key in production. cpass only ever verifies license tokens
// (internal/license's package doc comment); nothing in the CLI can mint
// one, and this tool is not imported by, and shares no code path with,
// cmd/cpass.
//
// Run it with the signing key injected by cpass itself, never typed or
// pasted directly, so the key stays out of any shell history or Agent
// Context:
//
//	cpass run --with license/signing-key -- \
//	    go run ./services/license/cmd/mint --sub owner@example.com --days 365
//
// The token is written to stdout and ONLY the token — nothing else ever
// goes there — so it pipes straight into an activation:
//
//	cpass license activate "$(cpass run --with license/signing-key -- \
//	    go run ./services/license/cmd/mint --sub owner@example.com --days 365)"
//
// Every other message (usage, errors) goes to stderr. Before the token is
// printed, a one-line audit record — timestamp, sub, plan, exp, jti, never
// the token itself — is appended to $LICENSE_MINT_AUDIT, or ./mint-audit.log
// if that is unset. The audit write happens first and mint fails closed on
// error: if the record cannot be written, no token is printed, so a token
// without a matching audit line can never exist.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"claudepass/internal/license"
	"claudepass/services/license/internal/config"
)

// EnvAuditLog names the environment variable that overrides where the
// audit log is appended; unset falls back to defaultAuditPath.
const EnvAuditLog = "LICENSE_MINT_AUDIT"

// defaultAuditPath is used when EnvAuditLog is unset: a file in the
// current directory, matching the tool's own "run it from a checkout of
// this repo" usage in its doc comment above.
const defaultAuditPath = "mint-audit.log"

// Exit codes, matching internal/cli's convention (this tool is otherwise
// independent of that package on purpose — see the doc comment above).
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr, time.Now))
}

// run implements the tool over injectable args/env/output/clock so tests
// never need a subprocess to exercise its logic (services/license/cmd/mint's
// own tests do that; internal/e2e additionally drives the real built
// binary end to end, per CLA-43's acceptance bullets).
func run(args []string, getenv func(string) string, stdout, stderr io.Writer, now func() time.Time) int {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: mint --sub <email> [--plan pro|free] --days <n>")
		_, _ = fmt.Fprintln(stderr)
		_, _ = fmt.Fprintln(stderr, "Mints an owner-issued ClaudePass license token (CLA-43) and prints it to")
		_, _ = fmt.Fprintln(stderr, "stdout. Requires "+config.EnvSigningKey+" in the environment — run this under")
		_, _ = fmt.Fprintln(stderr, "`cpass run --with license/signing-key --`, never with the key typed in by hand.")
		_, _ = fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}
	sub := fs.String("sub", "", "account email the token is issued to (required)")
	plan := fs.String("plan", license.PlanPro, "plan to issue: "+license.PlanPro+" or "+license.PlanFree)
	days := fs.Int("days", 0, "days until the token expires (required, > 0)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "mint: unexpected extra arguments: %v\n", fs.Args())
		fs.Usage()
		return exitUsage
	}
	if *sub == "" {
		_, _ = fmt.Fprintln(stderr, "mint: --sub is required")
		fs.Usage()
		return exitUsage
	}
	if *plan != license.PlanPro && *plan != license.PlanFree {
		_, _ = fmt.Fprintf(stderr, "mint: --plan must be %q or %q, got %q\n", license.PlanPro, license.PlanFree, *plan)
		return exitUsage
	}
	if *days <= 0 {
		_, _ = fmt.Fprintln(stderr, "mint: --days must be a positive integer")
		return exitUsage
	}

	rawKey := getenv(config.EnvSigningKey)
	if rawKey == "" {
		_, _ = fmt.Fprintf(stderr, "mint: %s is not set — run this under `cpass run --with license/signing-key --`\n", config.EnvSigningKey)
		return exitError
	}
	keyBytes, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
		_, _ = fmt.Fprintf(stderr, "mint: %s must be base64 of a %d-byte Ed25519 private key (the output of internal/license/cmd/keygen)\n",
			config.EnvSigningKey, ed25519.PrivateKeySize)
		return exitError
	}
	priv := ed25519.PrivateKey(keyBytes)

	t := now()
	exp := t.Add(time.Duration(*days) * 24 * time.Hour)
	jti, err := newJTI()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mint: %v\n", err)
		return exitError
	}

	token, err := license.Sign(priv, license.Payload{
		Sub:  *sub,
		Plan: *plan,
		Iat:  t.Unix(),
		Exp:  exp.Unix(),
		JTI:  jti,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mint: signing token: %v\n", err)
		return exitError
	}

	auditPath := getenv(EnvAuditLog)
	if auditPath == "" {
		auditPath = defaultAuditPath
	}
	// Audit first, print second: a token that could not be recorded must
	// never be handed out, so a stored token always has a matching line.
	if err := appendAudit(auditPath, auditRecord{
		Time: t.UTC().Format(time.RFC3339),
		Sub:  *sub,
		Plan: *plan,
		Exp:  exp.UTC().Format(time.RFC3339),
		JTI:  jti,
	}); err != nil {
		_, _ = fmt.Fprintf(stderr, "mint: writing audit log %s: %v\n", auditPath, err)
		return exitError
	}

	if _, err := fmt.Fprintln(stdout, token); err != nil {
		// The audit line is already written; say so, since the operator now
		// has a jti with no token to match it.
		_, _ = fmt.Fprintf(stderr, "mint: writing token to stdout (audit jti %s already recorded): %v\n", jti, err)
		return exitError
	}
	return exitOK
}

// auditRecord is one line of the mint audit log: everything about an
// issued token except the token itself, which must never be written to
// any log (internal/license's Verify doc comment; the same rule
// services/license/internal/server holds for its own request logging).
type auditRecord struct {
	Time string `json:"time"`
	Sub  string `json:"sub"`
	Plan string `json:"plan"`
	Exp  string `json:"exp"`
	JTI  string `json:"jti"`
}

// appendAudit appends one JSON-line audit record to path, creating it if
// needed. It never truncates: every past record stays, matching an audit
// log's one job.
func appendAudit(path string, rec auditRecord) (err error) {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	line = append(line, '\n')
	_, err = f.Write(line)
	return err
}

// newJTI mints a random token id the same way
// services/license/internal/server does, so an owner-issued token's jti
// looks exactly like a Stripe-issued one.
func newJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("reading random bytes for a token id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
