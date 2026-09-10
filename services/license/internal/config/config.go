// Package config loads the license service's configuration from the
// environment. Every value the service needs to run comes from here; no
// handler reads os.Getenv directly, so tests build a Config by hand instead
// of mutating the process environment.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
)

// Environment variable names. See services/license/README.md for the full
// deploy runbook these correspond to.
const (
	EnvAddr                = "LICENSE_ADDR"
	EnvBaseURL             = "LICENSE_BASE_URL"
	EnvDBPath              = "LICENSE_DB_PATH"
	EnvSigningKey          = "LICENSE_SIGNING_KEY"
	EnvStripeSecretKey     = "LICENSE_STRIPE_SECRET_KEY"
	EnvStripePriceID       = "LICENSE_STRIPE_PRICE_ID"
	EnvStripeWebhookSecret = "LICENSE_STRIPE_WEBHOOK_SECRET"
	EnvSMTPHost            = "LICENSE_SMTP_HOST"
	EnvSMTPPort            = "LICENSE_SMTP_PORT"
	EnvSMTPUsername        = "LICENSE_SMTP_USERNAME"
	EnvSMTPPassword        = "LICENSE_SMTP_PASSWORD"
	EnvSMTPFrom            = "LICENSE_SMTP_FROM"
)

// Config is everything a running service instance needs. Load builds one
// from the environment; tests construct one directly with a throwaway
// signing key and a fake Stripe/mailer instead.
type Config struct {
	// Addr is the address http.ListenAndServe binds, e.g. ":8080".
	Addr string
	// BaseURL is this service's own public URL, no trailing slash (e.g.
	// "https://claudepass.com"). Used to build the Checkout
	// success_url and the billing portal return_url.
	BaseURL string
	// DBPath is the SQLite file the store opens.
	DBPath string
	// SigningKey signs issued license tokens. It must be the exact private
	// key whose public half is embedded in internal/license (see
	// internal/license/cmd/keygen and the CLA-14 handoff) — a mismatched
	// key signs tokens the cpass binary will refuse.
	SigningKey ed25519.PrivateKey

	// StripeSecretKey authenticates Stripe API calls (sk_test_/sk_live_).
	StripeSecretKey string
	// StripePriceID is the recurring Price used for the one Checkout line
	// item ($9.99/month).
	StripePriceID string
	// StripeWebhookSecret verifies the Stripe-Signature header (whsec_...).
	StripeWebhookSecret string

	// SMTP* configure the mailer /reissue uses. All empty means no mailer
	// is configured; the service still runs (checkout/webhook/license work
	// fine) but /reissue refuses with a clear error instead of silently
	// discarding the token.
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
}

// Load reads Config from the environment. It fails on a missing or
// malformed required variable rather than starting with a half-usable
// service; SMTP variables are the one optional group (see SMTP* doc above).
func Load() (Config, error) {
	c := Config{
		Addr:                getenv(EnvAddr, ":8080"),
		BaseURL:             os.Getenv(EnvBaseURL),
		DBPath:              getenv(EnvDBPath, "license.db"),
		StripeSecretKey:     os.Getenv(EnvStripeSecretKey),
		StripePriceID:       os.Getenv(EnvStripePriceID),
		StripeWebhookSecret: os.Getenv(EnvStripeWebhookSecret),
		SMTPHost:            os.Getenv(EnvSMTPHost),
		SMTPPort:            getenv(EnvSMTPPort, "587"),
		SMTPUsername:        os.Getenv(EnvSMTPUsername),
		SMTPPassword:        os.Getenv(EnvSMTPPassword),
		SMTPFrom:            os.Getenv(EnvSMTPFrom),
	}

	var missing []string
	if c.BaseURL == "" {
		missing = append(missing, EnvBaseURL)
	}
	if c.StripeSecretKey == "" {
		missing = append(missing, EnvStripeSecretKey)
	}
	if c.StripePriceID == "" {
		missing = append(missing, EnvStripePriceID)
	}
	if c.StripeWebhookSecret == "" {
		missing = append(missing, EnvStripeWebhookSecret)
	}
	rawKey := os.Getenv(EnvSigningKey)
	if rawKey == "" {
		missing = append(missing, EnvSigningKey)
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment variable(s): %v", missing)
	}

	key, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return Config{}, fmt.Errorf("%s must be base64 of a %d-byte Ed25519 private key (the output of internal/license/cmd/keygen)", EnvSigningKey, ed25519.PrivateKeySize)
	}
	c.SigningKey = ed25519.PrivateKey(key)

	return c, nil
}

// MailerConfigured reports whether enough SMTP settings are present to send
// mail. /reissue refuses with a clear error instead of dropping the token
// when this is false.
func (c Config) MailerConfigured() bool {
	return c.SMTPHost != "" && c.SMTPFrom != ""
}

func getenv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
