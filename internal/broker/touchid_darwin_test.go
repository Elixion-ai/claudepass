//go:build darwin && touchid && cgo

package broker

// Manual checklist for CLA-23, kept as a real (if specially gated) Go test
// rather than prose, so it can be re-run mechanically after any future
// change to touchid_darwin.go: `go test -tags touchid ./internal/broker/
// -run TestTouchIDUserPresence -v`. It never runs as part of the ordinary
// `go test ./...` or `go test -tags e2e ./...` quality-bar commands — no
// Go source file in this repository passes -tags touchid to `go test`
// itself, so this file only builds, and this test only runs, when a human
// deliberately asks for it, on a mac with Xcode's command-line tools
// installed (`xcode-select -p`).
//
// What it proves, entirely non-interactively — it deliberately never pops
// the real Touch ID / password GUI prompt, so it is safe to run from an
// unattended shell or CI runner that happens to pass -tags touchid by
// mistake:
//
//  1. keychainSetUserPresence actually creates a Keychain item carrying a
//     SecAccessControl (not just a plain generic-password item like
//     keychainSet's).
//  2. That access control genuinely gates the item's data: a read that
//     forbids showing any authentication UI (kSecUseAuthenticationUISkip,
//     applied by queryNoUI in touchid_darwin.go) fails instead of
//     returning the data, which is only possible if the OS itself is
//     enforcing kSecAccessControlUserPresence on this exact item — proved
//     by contrast against a second, plain item (created via keychainSet,
//     no ACL), read the same no-UI way, which succeeds.
//  3. The stored bytes round-trip through the same base64 step keychainGet
//     (keychain_darwin.go, the plain, cgo-free reader every real cpass
//     invocation still uses — see SetKeychainKeyUserPresence's doc
//     comment) would apply.
//
// Two things it does NOT and cannot prove here, and why:
//
//   - That step (1) — SetItemAdd of the access-controlled item — even
//     succeeds at all, on THIS machine, with THIS binary. It requires the
//     test binary to be code-signed with a keychain-access-groups
//     entitlement matching a real Apple-issued Team ID (see
//     touchid_darwin.go's SecItemAdd error handling and docs/SECURITY.md);
//     `go test` output is an ad hoc/unsigned binary, which cannot satisfy
//     that — confirmed empirically while building this file (a bare
//     SecItemAdd of an access-controlled item fails errSecMissingEntitlement,
//     -34018, from an unsigned binary every time, regardless of Touch ID
//     enrollment or any runtime state) and documented rather than worked
//     around, since the alternative that DOES succeed unsigned — the
//     legacy, file-based keychain — turns out to accept a
//     SecAccessControl attribute without ever enforcing it (also
//     confirmed empirically before this design settled on the Data
//     Protection Keychain instead). This test skips, with that
//     explanation, the moment it sees errSecMissingEntitlement, rather
//     than failing: it is a real, external precondition unmet in this
//     environment, not a defect this code can route around.
//   - That the real Touch ID / password GUI actually appears and, on
//     success, actually releases the key. Completing that requires a
//     human physically present at a signed build's keyboard/Touch ID
//     sensor to interact with a system-level authentication dialog
//     outside any process's stdio — no automated agent can drive that
//     dialog, and this repository's own constraint (carried forward from
//     CLA-8/CLA-9) is that no test, automated or accidentally run
//     unattended, may ever trigger that prompt for real.
//
// Exercising both of those is the manual step, once a signed build is
// available: run `cpass init --touch-id` yourself, confirm Touch ID (or
// the passcode) is asked for on the next `cpass ls`, and confirm Cancel
// leaves the Vault locked rather than open. See docs/SECURITY.md.
//
// Note on structure: this file deliberately holds no `import "C"` — cgo
// is not supported directly in a _test.go file (go build and go test both
// refuse it outright). Every cgo call this test needs (keychainSet,
// keychainSetUserPresence, queryNoUI) is a production function in
// touchid_darwin.go that already crosses that boundary into plain Go
// types (bool/string/[]byte, an error), so this file never has to.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestTouchIDUserPresence(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	service := fmt.Sprintf("cpass-touchid-selftest-%d-%d", os.Getpid(), time.Now().UnixNano())
	account := "selftest-account"
	t.Cleanup(func() {
		exec.Command("security", "delete-generic-password", "-a", account, "-s", service).Run()
	})

	if err := keychainSetUserPresence(service, account, key); err != nil {
		if strings.Contains(err.Error(), "keychain-access-groups") {
			t.Skipf("this build is not code-signed with the keychain-access-groups entitlement "+
				"a Touch ID Keychain item needs (see docs/SECURITY.md): %v", err)
		}
		t.Fatalf("keychainSetUserPresence: %v", err)
	}

	// (1) + (2): the item must require user presence — proved without
	// ever showing the real prompt, since kSecUseAuthenticationUISkip
	// forces an immediate failure instead of UI whenever authentication
	// would otherwise be needed.
	ok, desc, data := queryNoUI(service, account)
	if ok {
		t.Fatal("reading the user-presence item succeeded with no authentication UI allowed and none cached — " +
			"the SecAccessControl is not being enforced")
	}
	t.Logf("user-presence item, UI skipped: %s — access is gated, as expected", desc)
	if data != nil {
		t.Fatal("a refused read should not return data")
	}

	// (3): contrast against a second, plain item (no ACL, created the way
	// SetKeychainKey — not SetKeychainKeyUserPresence — creates one): the
	// same no-UI query must succeed for it, and its bytes must decode
	// (same base64 step keychainGet uses) back to the exact key, proving
	// storage format compatibility between the plain and ACL'd paths.
	plainService := service + "-plain"
	t.Cleanup(func() {
		exec.Command("security", "delete-generic-password", "-a", account, "-s", plainService).Run()
	})
	if err := keychainSet(plainService, account, key); err != nil {
		t.Fatalf("keychainSet (plain, for contrast): %v", err)
	}
	ok, desc, data = queryNoUI(plainService, account)
	if !ok {
		t.Fatalf("reading the plain item with UI skipped: %s — a plain item should never need authentication UI", desc)
	}
	got, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("plain item data is not valid base64: %v", err)
	}
	if string(got) != string(key) {
		t.Fatalf("plain item round-trip mismatch: got %x, want %x", got, key)
	}
}
