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

// TestKeyCacheSlidesIdleWindowForwardOnEachCall proves the window is a
// sliding idle timeout, not a fixed TTL counted from the first fetch —
// mirroring process_unix.go's own Broker, whose Accept deadline resets on
// every request: a cache kept busy by calls spaced closer together than
// idle must never re-derive on its own.
func TestKeyCacheSlidesIdleWindowForwardOnEachCall(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x55}, vault.KeySize)
	t.Setenv(EnvKey, base64.StdEncoding.EncodeToString(k1))

	c := NewKeyCache(60 * time.Millisecond)
	for i := 0; i < 5; i++ {
		got, err := c.Key()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, k1) {
			t.Fatalf("call %d: got %x, want k1", i, got)
		}
		time.Sleep(30 * time.Millisecond) // well under idle, keeps sliding it forward
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
