package broker

import (
	"sync"
	"time"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

// KeyCache holds an unlock key across repeated Broker operations within a
// bounded TTL, so a caller that makes many calls from one long-lived
// process (cpass mcp) does not re-derive the key — on the macOS Keychain
// path, a `security` subprocess, ~15ms and ~24x the in-process cost — on
// every single one (CLA-77). A CLI invocation never constructs one: it
// makes at most a couple of Broker calls before the process exits, so
// there is nothing to amortise, and Resolve/OpenVault above stay the
// always-fresh default for it and every other caller.
//
// The bound is a TTL from when the key was last (re-)derived, not a
// deadline that slides forward on every hit: see Key's own doc comment for
// why activity must not be able to extend it. That non-renewable bound,
// not a per-item ACL check, is what keeps a cached key from silently
// outliving `cpass lock` or a rotated Keychain item: cpass ships
// CGO_ENABLED=0 by default (ADR-0007), so the Keychain reader this sits in
// front of (keychain_darwin.go's keychainGet) cannot tell a user-presence
// (Touch ID) item from a plain one — only whether the read itself
// succeeds, which is also the only signal a `security`(1) subprocess call
// ever gave `cpass` to begin with. Bounding every cached key to
// DefaultIdleTimeout — the same window the Linux/CI Broker process already
// uses to hold a key in memory — means this cache is never a longer-lived
// secret than the one the Broker itself already treats as an acceptable
// risk, Touch ID-protected Keychain item or not. See ADR-0004 and
// docs/SECURITY.md's Touch ID section, which documents this cache
// explicitly for that reason.
type KeyCache struct {
	idle time.Duration

	mu  sync.Mutex
	key []byte
	at  time.Time
}

// NewKeyCache returns a KeyCache whose key re-derives once idle has
// elapsed since it was last fetched, whether or not calls kept arriving in
// between. Pass DefaultIdleTimeout to match the Broker's own default.
func NewKeyCache(idle time.Duration) *KeyCache {
	return &KeyCache{idle: idle}
}

// Key returns the cached key if it was last (re-)derived within idle,
// re-deriving it through UnlockKey() otherwise. This is a TTL anchored to
// that last derivation, not a deadline a hit slides forward: a cache kept
// continuously busy — the ordinary case for an active Agent session
// driving cpass mcp — must still re-derive once idle has elapsed, the same
// as one that went briefly idle first. A version of this that reset the
// clock on every hit shipped and was live-reproduced to defeat `cpass
// lock` entirely against a busy process (CLA-77): as long as calls kept
// arriving closer together than idle, the window never elapsed and the
// stale key was served forever. With the TTL, the very next call after
// idle has elapsed re-checks UnlockKey() regardless of how busy the cache
// has been — the bounded re-check that keeps `cpass lock` (on the
// Broker-socket path) or a changed/removed Keychain item from being
// silently ignored for longer than one idle window (see
// docs/SECURITY.md's "within one idle window, not instantly").
func (c *KeyCache) Key() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key != nil && time.Since(c.at) < c.idle {
		return append([]byte(nil), c.key...), nil
	}
	// The expired key is zeroed before it is dropped (CLA-60). Callers only
	// ever receive a copy, so zeroing the cache's own slice can never
	// corrupt a key another goroutine is still passing to vault.Open.
	zeroKey(c.key)
	key, err := UnlockKey()
	if err != nil {
		c.key, c.at = nil, time.Time{}
		return nil, err
	}
	c.key, c.at = key, time.Now()
	return append([]byte(nil), key...), nil
}

// OpenVault opens the Vault using Key() in place of UnlockKey(), the same
// way OpenVault() does otherwise.
func (c *KeyCache) OpenVault() (*vault.Vault, error) {
	p, err := VaultPath()
	if err != nil {
		return nil, err
	}
	key, err := c.Key()
	if err != nil {
		return nil, err
	}
	return vault.Open(p, key)
}

// Resolve is Resolve, sourcing its unlock key from c instead of calling
// OpenVault() (and so UnlockKey()) fresh. CI mode still resolves from the
// environment and never touches c, exactly like Resolve.
func (c *KeyCache) Resolve(refs []Ref) ([]Resolved, []string, error) {
	if len(refs) == 0 {
		return nil, nil, nil
	}
	if CIMode() {
		return resolveFromEnv(refs)
	}
	v, err := c.OpenVault()
	if err != nil {
		return nil, nil, err
	}
	defer v.Close()
	return resolveFromVault(v, refs)
}

// UpdateVault is UpdateVault, sourcing its unlock key from c: fn runs
// under vault.Update's exclusive file lock against a freshly reopened
// Vault, which is saved if fn returns nil and zeroed either way. The file
// lock excludes concurrent writers in this process as well as in any
// other cpass process (CLA-55), so cpass mcp needs no mutex of its own
// around a write tool call.
func (c *KeyCache) UpdateVault(fn func(v *vault.Vault) error) error {
	p, err := VaultPath()
	if err != nil {
		return err
	}
	key, err := c.Key()
	if err != nil {
		return err
	}
	defer zeroKey(key)
	return vault.Update(p, key, fn)
}

// zeroKey overwrites b in place; see vault.Vault.Close for what zeroing a
// key in Go can and cannot promise.
func zeroKey(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
