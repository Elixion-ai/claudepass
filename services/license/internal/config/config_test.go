package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// setEnv sets every required variable to a valid value, then applies
// overrides, restoring the environment after the test.
func setEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]string{
		EnvBaseURL:             "https://license.example.test",
		EnvStripeSecretKey:     "sk_test_123",
		EnvStripePriceID:       "price_123",
		EnvStripeWebhookSecret: "whsec_123",
		EnvSigningKey:          base64.StdEncoding.EncodeToString(priv),
	}
	for k, v := range overrides {
		if v == "" {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	allVars := []string{EnvAddr, EnvBaseURL, EnvDBPath, EnvSigningKey, EnvStripeSecretKey,
		EnvStripePriceID, EnvStripeWebhookSecret, EnvSMTPHost, EnvSMTPPort, EnvSMTPUsername,
		EnvSMTPPassword, EnvSMTPFrom}
	for _, k := range allVars {
		os.Unsetenv(k)
	}
	for k, v := range base {
		os.Setenv(k, v)
	}
	t.Cleanup(func() {
		for _, k := range allVars {
			os.Unsetenv(k)
		}
	})
}

func TestLoadSucceedsWithAllRequiredVars(t *testing.T) {
	setEnv(t, nil)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Addr != ":8080" {
		t.Fatalf("Addr default = %q, want :8080", c.Addr)
	}
	if c.DBPath != "license.db" {
		t.Fatalf("DBPath default = %q, want license.db", c.DBPath)
	}
	if len(c.SigningKey) != ed25519.PrivateKeySize {
		t.Fatalf("SigningKey length = %d, want %d", len(c.SigningKey), ed25519.PrivateKeySize)
	}
	if c.MailerConfigured() {
		t.Fatal("MailerConfigured should be false when no SMTP vars are set")
	}
}

func TestLoadReportsEveryMissingVar(t *testing.T) {
	setEnv(t, map[string]string{EnvBaseURL: "", EnvStripePriceID: ""})
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{EnvBaseURL, EnvStripePriceID} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q should mention missing var %s", err, want)
		}
	}
}

func TestLoadRejectsMalformedSigningKey(t *testing.T) {
	setEnv(t, map[string]string{EnvSigningKey: "not-base64!!"})
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error for a malformed signing key")
	}
}

func TestLoadRejectsWrongLengthSigningKey(t *testing.T) {
	setEnv(t, map[string]string{EnvSigningKey: base64.StdEncoding.EncodeToString([]byte("too-short"))})
	_, err := Load()
	if err == nil {
		t.Fatal("expected an error for a short signing key")
	}
}

func TestMailerConfiguredRequiresHostAndFrom(t *testing.T) {
	setEnv(t, map[string]string{EnvSMTPHost: "smtp.example.test"})
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.MailerConfigured() {
		t.Fatal("should require SMTP_FROM too")
	}
	setEnv(t, map[string]string{EnvSMTPHost: "smtp.example.test", EnvSMTPFrom: "license@example.test"})
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.MailerConfigured() {
		t.Fatal("should be configured once both host and from are set")
	}
}
