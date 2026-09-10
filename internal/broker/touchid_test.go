package broker

import (
	"errors"
	"strings"
	"testing"
)

// TestTouchIDUnavailableInDefaultBuild is CLA-23's core unit test: it runs
// under the module's default `go test ./...` — no -tags touchid, so
// touchid_stub.go (not touchid_darwin.go) provides these functions
// regardless of GOOS — and asserts that the non-cgo fallback path is what
// actually gets selected: TouchIDAvailable reports false, and both
// Touch-ID-only entry points refuse with ErrTouchIDUnsupported rather than
// silently doing something else. This is exactly the guarantee CLAUDE.md
// and ADR-0007 need held: the CGO_ENABLED=0 release build, and every
// ordinary `go build`/`go test` invocation, never gains a dependency on
// the Security framework or a way to trigger its access-control UI.
func TestTouchIDUnavailableInDefaultBuild(t *testing.T) {
	if TouchIDAvailable() {
		t.Fatal("TouchIDAvailable() is true in a binary built without -tags touchid; " +
			"the CGO_ENABLED=0 default build must never report Touch ID support")
	}

	if err := SetKeychainKeyUserPresence([]byte("0123456789012345678901234567890")); !errors.Is(err, ErrTouchIDUnsupported) {
		t.Fatalf("SetKeychainKeyUserPresence() = %v, want ErrTouchIDUnsupported", err)
	}

	if _, err := GetKeychainKeyUserPresence(); !errors.Is(err, ErrTouchIDUnsupported) {
		t.Fatalf("GetKeychainKeyUserPresence() = %v, want ErrTouchIDUnsupported", err)
	}
}

// TestErrTouchIDUnsupportedMentionsTheFix guards the one thing a human
// reading this error actually needs: how to get Touch ID support, so a
// refusal is actionable rather than a dead end.
func TestErrTouchIDUnsupportedMentionsTheFix(t *testing.T) {
	msg := ErrTouchIDUnsupported.Error()
	for _, want := range []string{"touchid", "CGO_ENABLED=1"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("ErrTouchIDUnsupported = %q, want it to mention %q", msg, want)
		}
	}
}
