package broker

import (
	"strings"
	"testing"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

// ciEnv puts Resolve into CI mode with a clean environment, so these tests
// exercise the resolution rules without needing a Vault on disk.
func ciEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvCI, "1")
}

func TestGlobalRefBindingCollisionIsRefused(t *testing.T) {
	ciEnv(t)
	t.Setenv("SHARED_VAR", "value-from-the-environment")
	refs := []Ref{
		{Handle: "openai/key", Declared: vault.Binding{Name: "SHARED_VAR"}, FromGlobal: true},
		{Handle: "stripe/live", Declared: vault.Binding{Name: "SHARED_VAR"}},
	}
	_, _, err := Resolve(refs)
	if err == nil {
		t.Fatal("two Handles binding one variable, one of them Global, must be refused")
	}
	for _, want := range []string{"handle collision", "openai/key", "stripe/live", "SHARED_VAR"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q must name %q", err, want)
		}
	}
}

// TestProjectOnlyCollisionKeepsTodaysBehaviour is the backward-compatibility
// guard: a project that has two Handles bound to one variable has always
// resolved them last-write-wins, silently. Introducing the Global Manifest
// must not turn that into a failure for a project that never opted in.
func TestProjectOnlyCollisionKeepsTodaysBehaviour(t *testing.T) {
	ciEnv(t)
	t.Setenv("SHARED_VAR", "value-from-the-environment")
	refs := []Ref{
		{Handle: "openai/key", Declared: vault.Binding{Name: "SHARED_VAR"}},
		{Handle: "stripe/live", Declared: vault.Binding{Name: "SHARED_VAR"}},
	}
	out, _, err := Resolve(refs)
	if err != nil {
		t.Fatalf("a collision between two project Handles must not start failing: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("resolved: %+v", out)
	}
}

func TestUnresolvableGlobalRefIsSkippedNotFatal(t *testing.T) {
	ciEnv(t)
	t.Setenv("STRIPE_LIVE", "value-from-the-environment")
	refs := []Ref{
		{Handle: "openai/key", FromGlobal: true}, // OPENAI_KEY is not set
		{Handle: "stripe/live"},
	}
	out, skipped, err := Resolve(refs)
	if err != nil {
		t.Fatalf("one drifted Global declaration must not fail the run: %v", err)
	}
	if len(out) != 1 || out[0].Handle != "stripe/live" {
		t.Fatalf("the resolvable Handles must still be injected: %+v", out)
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped: %v", skipped)
	}
	for _, want := range []string{"openai/key", "Global Manifest", "OPENAI_KEY is not set", "cpass local"} {
		if !strings.Contains(skipped[0], want) {
			t.Fatalf("notice %q must name %q", skipped[0], want)
		}
	}
}

// TestUnresolvableProjectRefStillFails: a project's committed Manifest is a
// contract, and a Handle it names that cannot be resolved is still fatal.
// Only the ambient Global layer degrades gracefully.
func TestUnresolvableProjectRefStillFails(t *testing.T) {
	ciEnv(t)
	_, _, err := Resolve([]Ref{{Handle: "openai/key"}})
	if err == nil || !strings.Contains(err.Error(), "openai/key") {
		t.Fatalf("want a fatal error naming the Handle, got %v", err)
	}
	// Same for one the caller asked for explicitly with --with.
	_, _, err = Resolve([]Ref{{Handle: "openai/key", Override: "ANYTHING"}})
	if err == nil {
		t.Fatal("an explicitly requested Handle must still be fatal when missing")
	}
}

func TestFromGlobalSurvivesResolution(t *testing.T) {
	ciEnv(t)
	t.Setenv("OPENAI_KEY", "value-from-the-environment")
	out, _, err := Resolve([]Ref{{Handle: "openai/key", FromGlobal: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || !out[0].FromGlobal {
		t.Fatalf("FromGlobal must reach the injection step: %+v", out)
	}
}
