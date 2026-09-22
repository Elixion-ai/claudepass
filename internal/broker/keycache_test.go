package broker

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

// TestKeyCacheReusesKeyWithinIdleWindow is CLA-77's core regression test:
// once Key() has succeeded, a later call within the idle window must keep
// serving that same key rather than re-deriving it — the whole point of
// the cache — even if the underlying source changed in the meantime.
func TestKeyCacheReusesKeyWithinIdleWindow(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x11}, vault.KeySize)
	k2 := bytes.Repeat([]byte{0x22}, vault.KeySize)
	t.Setenv(EnvKey, base64.StdEncoding.EncodeToString(k1))

	c := NewKeyCache(time.Hour)
	got, err := c.Key()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, k1) {
		t.Fatalf("first Key(): got %x, want k1", got)
	}

	// The underlying source changed, but the cache is still well within its
	// idle window: it must keep serving the key it already fetched, not
	// re-read UnlockKey() on every call.
	t.Setenv(EnvKey, base64.StdEncoding.EncodeToString(k2))
	got, err = c.Key()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, k1) {
		t.Fatalf("Key() within the idle window: got %x, want the still-cached k1", got)
	}
}

// TestKeyCacheRederivesAfterIdle is the other half of CLA-77's constraint:
// once the idle window has actually elapsed with no calls, the cache
// re-checks UnlockKey() rather than serving a stale key forever — the
// bounded re-check that keeps `cpass lock` (Broker-socket path) or a
// rotated Keychain item from being silently ignored past DefaultIdleTimeout
// (see docs/SECURITY.md's Touch ID section and ADR-0004).
func TestKeyCacheRederivesAfterIdle(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x33}, vault.KeySize)
	k2 := bytes.Repeat([]byte{0x44}, vault.KeySize)
	t.Setenv(EnvKey, base64.StdEncoding.EncodeToString(k1))

	c := NewKeyCache(20 * time.Millisecond)
	if _, err := c.Key(); err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvKey, base64.StdEncoding.EncodeToString(k2))
	time.Sleep(40 * time.Millisecond)

	got, err := c.Key()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, k2) {
		t.Fatalf("Key() past idle: got %x, want the re-derived k2", got)
	}
}

// TestKeyCacheTTLDoesNotRenewOnActivity is CLA-77's fix for the sliding
// window this test used to assert as correct: the cached key's lifetime is
// a TTL anchored to when it was last (re-)derived, not a deadline that
// slides forward on every hit. A cache kept continuously busy — the
// ordinary case for an active Agent session driving cpass mcp — must still
// re-derive once idle has elapsed since that anchor, the same as one that
// went idle first (TestKeyCacheRederivesAfterIdle), even though every call
// along the way was spaced well under idle apart. The old sliding
// behaviour meant a busy `cpass mcp` process never re-derived at all,
// defeating `cpass lock` for the rest of its life — see
// TestKeyCacheHonorsALockEvenWhenKeptBusy below for that exact scenario.
func TestKeyCacheTTLDoesNotRenewOnActivity(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x55}, vault.KeySize)
	k2 := bytes.Repeat([]byte{0x88}, vault.KeySize)
	t.Setenv(EnvKey, base64.StdEncoding.EncodeToString(k1))

	const idle = 60 * time.Millisecond
	c := NewKeyCache(idle)
	start := time.Now()
	for time.Since(start) < 45*time.Millisecond {
		got, err := c.Key()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, k1) {
			t.Fatalf("call within the TTL: got %x, want the still-cached k1", got)
		}
		time.Sleep(15 * time.Millisecond) // well under idle: keeps the cache "busy"
	}

	t.Setenv(EnvKey, base64.StdEncoding.EncodeToString(k2))
	// Wait past idle measured from the FIRST fetch (start), not from the
	// last call above: a sliding window would still have most of its
	// budget left here (the last call was well under idle ago); a
	// non-renewable TTL must not.
	for time.Since(start) < idle+20*time.Millisecond {
		time.Sleep(5 * time.Millisecond)
	}

	got, err := c.Key()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, k2) {
		t.Fatalf("call past idle (measured from first fetch) despite continuous activity: got %x, want the re-derived k2 — the window renewed on activity instead of expiring", got)
	}
}

// TestKeyCacheHonorsALockEvenWhenKeptBusy is CLA-77's own regression test,
// on the scenario the finding live-reproduced: the Broker-socket path
// (CPASS_UNLOCK=socket), where `cpass lock` makes the key source vanish
// (nothing left listening on the socket, simulated here the same way
// TestKeyCacheDropsAKeyThatFailedToRederive does, by clearing CPASS_KEY
// with no Broker running). A KeyCache whose calls never stop coming —
// closer together than idle, the whole way through — must still notice
// within one idle window of its last derivation, not keep serving the
// pre-lock key for as long as the process stays busy.
func TestKeyCacheHonorsALockEvenWhenKeptBusy(t *testing.T) {
	t.Setenv(EnvHome, t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv(EnvUnlock, "socket")
	k1 := bytes.Repeat([]byte{0x77}, vault.KeySize)
	t.Setenv(EnvKey, base64.StdEncoding.EncodeToString(k1))

	const idle = 60 * time.Millisecond
	c := NewKeyCache(idle)
	start := time.Now()
	lockedYet := false
	var lastErr error
	for time.Since(start) < idle+40*time.Millisecond {
		if !lockedYet && time.Since(start) > 15*time.Millisecond {
			t.Setenv(EnvKey, "") // simulate `cpass lock`: no key source left
			lockedYet = true
		}
		if _, lastErr = c.Key(); lastErr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond) // well under idle: keeps the cache "busy"
	}
	if lastErr == nil {
		t.Fatal("a KeyCache kept continuously busy never noticed cpass lock: it would keep serving the pre-lock key for the rest of a busy cpass mcp process's life")
	}
}

// TestKeyCacheDropsAKeyThatFailedToRederive proves a failed re-derivation
// (e.g. the key source went away) does not leave a stale key cached for the
// next call to keep serving as if nothing had changed. CPASS_UNLOCK=socket
// forces the Broker-socket path once CPASS_KEY is cleared, with CPASS_HOME
// pointed at an empty temp dir and no Broker running there, so this never
// touches a real Keychain item or a real Broker socket.
func TestKeyCacheDropsAKeyThatFailedToRederive(t *testing.T) {
	t.Setenv(EnvHome, t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv(EnvUnlock, "socket")
	k1 := bytes.Repeat([]byte{0x66}, vault.KeySize)
	t.Setenv(EnvKey, base64.StdEncoding.EncodeToString(k1))

	c := NewKeyCache(10 * time.Millisecond)
	if _, err := c.Key(); err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvKey, "") // the source is gone, and nothing is listening on the socket either
	time.Sleep(20 * time.Millisecond)
	if _, err := c.Key(); err == nil {
		t.Fatal("want an error once the key source is gone and the cache is stale")
	}
}
