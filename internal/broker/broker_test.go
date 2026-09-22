package broker

import (
	"strings"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

// TestResolveFromEnvRefusesShortValue is the regression test for CLA-69:
// resolveFromEnv used to resolve any non-empty environment value, with no
// floor, even though vault.Add refuses anything shorter than
// vault.MinSecretLength (8 bytes) precisely because redact.minPatternLen
// (6) assumes every Secret clears it. A short CI-resolved value got zero
// redact Patterns and printed raw the moment a wrapped command echoed it.
// A project-declared Handle (not FromGlobal) must hard-fail exactly like
// the existing "not set in the environment" case just above it.
func TestResolveFromEnvRefusesShortValue(t *testing.T) {
	ciEnv(t)
	const tooShort = "zqx9"
	t.Setenv("STRIPE_LIVE", tooShort)
	if len(tooShort) >= vault.MinSecretLength {
		t.Fatalf("test fixture must be shorter than vault.MinSecretLength (%d)", vault.MinSecretLength)
	}
	_, _, err := Resolve([]Ref{{Handle: "stripe/live"}})
	if err == nil {
		t.Fatal("a CI-resolved value shorter than vault.MinSecretLength must be refused, not silently used")
	}
	for _, want := range []string{"stripe/live", "STRIPE_LIVE", "8"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q must name the Handle and the minimum (%q missing)", err, want)
		}
	}
	if strings.Contains(err.Error(), tooShort) {
		t.Fatalf("error %q must never name the value itself", err)
	}
}

// TestResolveFromEnvSkipsShortGlobalValue mirrors
// TestUnresolvableGlobalRefIsSkippedNotFatal (globalref_test.go): a Global
// Handle degrades gracefully (skipped with a notice) rather than failing
// the whole run, and a too-short value gets the same treatment as a
// missing one.
func TestResolveFromEnvSkipsShortGlobalValue(t *testing.T) {
	ciEnv(t)
	t.Setenv("OPENAI_KEY", "shrt")
	out, skipped, err := Resolve([]Ref{{Handle: "openai/key", FromGlobal: true}})
	if err != nil {
		t.Fatalf("a too-short Global value must be skipped, not fatal: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("resolved: %+v, want nothing injected", out)
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped: %v", skipped)
	}
	for _, want := range []string{"openai/key", "Global Manifest", "OPENAI_KEY", "cpass local"} {
		if !strings.Contains(skipped[0], want) {
			t.Fatalf("notice %q must name %q", skipped[0], want)
		}
	}
}

// TestResolveFromEnvAcceptsValueAtMinLength is the boundary check: exactly
// vault.MinSecretLength characters must still resolve normally (this is a
// floor, not an off-by-one-stricter cap).
func TestResolveFromEnvAcceptsValueAtMinLength(t *testing.T) {
	ciEnv(t)
	val := strings.Repeat("x", vault.MinSecretLength)
	t.Setenv("STRIPE_LIVE", val)
	out, _, err := Resolve([]Ref{{Handle: "stripe/live"}})
	if err != nil {
		t.Fatalf("a value exactly at vault.MinSecretLength must resolve: %v", err)
	}
	if len(out) != 1 || out[0].Value != val {
		t.Fatalf("resolved: %+v", out)
	}
}
