package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This file is CLA-23's e2e coverage: the built cpass binary here is
// always compiled with `-tags e2e` only (see TestMain) — never `touchid`
// — so every test in this file exercises exactly the non-cgo fallback
// path a CGO_ENABLED=0 release binary takes, the same path selection unit
// -tested directly in internal/broker/touchid_test.go. None of them can
// pop a real Touch ID / password GUI prompt: the code that could do that
// (internal/broker/touchid_darwin.go) is not part of this binary at all.

// TestInitTouchIDFallsBackOffKeychainPath drives `cpass init --touch-id`
// down the non-macOS-Keychain unlock source (forced with CPASS_UNLOCK=
// socket, so this runs the same on Linux and macOS CI alike): --touch-id
// only means anything for the Keychain path, so init must say so and fall
// through to the ordinary passphrase flow rather than erroring out.
func TestInitTouchIDFallsBackOffKeychainPath(t *testing.T) {
	ve := lockedVault(t)
	env := socketEnv(t)
	r := ve.runEnv(env, []byte("a passphrase for this test\n"), "init", "--touch-id")
	if r.code != 0 {
		t.Fatalf("init --touch-id off the Keychain path: %s", r)
	}
	if !strings.Contains(r.stderr, "ignoring it") {
		t.Fatalf("want a clear notice that --touch-id was ignored: %s", r)
	}
	if !strings.Contains(r.stderr, "cpass unlock") {
		t.Fatalf("should still fall through to the ordinary passphrase flow: %s", r)
	}
}

// TestInitTouchIDFallsBackToPlainKeychainItem is the macOS acceptance path
// for the fallback: `cpass init --touch-id`, run by a binary with no
// Touch ID support compiled in, still creates a working Vault — the plain,
// unchanged Keychain item from before this issue — while clearly warning
// that Touch ID was requested but unavailable. This is the "falls back
// gracefully... since CLAUDE.md/CONTEXT.md still want cpass to build as a
// single portable binary" requirement from CLA-23.
func TestInitTouchIDFallsBackToPlainKeychainItem(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the macOS Keychain path only exists on darwin")
	}
	service := uniqueKeychainService(t)
	ve := lockedVault(t)
	env := []string{"CPASS_KEYCHAIN_SERVICE=" + service}
	t.Cleanup(func() {
		exec.Command("security", "delete-generic-password", "-a", ve.vaultPath(), "-s", service).Run()
	})

	r := ve.runEnv(env, nil, "init", "--touch-id")
	if r.code != 0 {
		t.Fatalf("init --touch-id: %s", r)
	}
	if !strings.Contains(r.stderr, "storing the key without Touch ID") {
		t.Fatalf("want a clear fallback notice naming Touch ID as unavailable: %s", r)
	}
	if !strings.Contains(r.stderr, "-tags touchid") {
		t.Fatalf("fallback notice should say how to get Touch ID support: %s", r)
	}

	// The Vault must still be fully usable with no CPASS_KEY, exactly like
	// the plain (no --touch-id) path CLA-8 already covers — this proves
	// the fallback really did store a working, plain Keychain item rather
	// than merely warning and leaving the Vault half-initialised.
	r = ve.runEnv(env, []byte("touchid-fallback-secret\n"), "add", "k/one")
	if r.code != 0 {
		t.Fatalf("add after init --touch-id fallback: %s", r)
	}
	r = ve.runEnv(env, nil, "ls")
	if r.code != 0 || !strings.Contains(r.stdout, "k/one") {
		t.Fatalf("ls after init --touch-id fallback: %s", r)
	}
}

// TestKeychainUpgradeFlagParsing covers the subcommand/flag surface of
// `cpass keychain upgrade --touch-id` that does not depend on the platform
// or build: no subcommand, an unknown one, and upgrade without --touch-id.
func TestKeychainUpgradeFlagParsing(t *testing.T) {
	ve := newVault(t)

	if r := ve.run(nil, "keychain"); r.code != 2 {
		t.Fatalf("keychain with no subcommand: want usage error, got %s", r)
	}
	if r := ve.run(nil, "keychain", "frobnicate"); r.code != 2 || !strings.Contains(r.stderr, "unknown keychain subcommand") {
		t.Fatalf("keychain frobnicate: want unknown-subcommand usage error, got %s", r)
	}
	if r := ve.run(nil, "keychain", "upgrade"); r.code != 2 || !strings.Contains(r.stderr, "--touch-id") {
		t.Fatalf("keychain upgrade with no --touch-id: want usage error naming the flag, got %s", r)
	}
}

// TestKeychainUpgradeRefusedWithoutBuildTag is the "upgrade" mirror of
// TestInitTouchIDFallsBackToPlainKeychainItem: unlike init, upgrade has no
// Vault-creation step it must still complete, so it refuses outright
// (ExitError, not a warning-and-continue) when this binary was not built
// with Touch ID support, rather than silently leaving an existing
// Keychain item unchanged while claiming success.
func TestKeychainUpgradeRefusedWithoutBuildTag(t *testing.T) {
	ve := lockedVault(t) // no init needed: the refusal fires before UnlockKey().
	r := ve.run(nil, "keychain", "upgrade", "--touch-id")
	if r.code == 0 {
		t.Fatalf("keychain upgrade --touch-id should be refused in a binary without -tags touchid: %s", r)
	}
	if runtime.GOOS != "darwin" {
		if !strings.Contains(r.stderr, "macOS-only") {
			t.Fatalf("off darwin, want a macOS-only refusal: %s", r)
		}
		return
	}
	if !strings.Contains(r.stderr, "touchid") || !strings.Contains(r.stderr, "CGO_ENABLED=1") {
		t.Fatalf("on darwin without -tags touchid, want ErrTouchIDUnsupported's message: %s", r)
	}
}

// uniqueKeychainService returns a throwaway CPASS_KEYCHAIN_SERVICE value,
// unique per call, so a test never collides with a real "cpass" Keychain
// item or with another test running concurrently — the same scheme
// TestKeychainUnlockRoundTrip (unlock_test.go) uses.
func uniqueKeychainService(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("cpass-e2e-touchid-test-%d-%d", os.Getpid(), time.Now().UnixNano())
}
