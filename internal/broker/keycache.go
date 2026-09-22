package broker

import (
	"sync"
	"time"

	"github.com/Elixion-ai/claudepass/internal/vault"
)

// KeyCache holds an unlock key across repeated Broker operations within a
// bounded idle window, so a caller that makes many calls from one
// long-lived process (cpass mcp) does not re-derive the key — on the
// macOS Keychain path, a `security` subprocess, ~15ms and ~24x the
// in-process cost — on every single one (CLA-77). A CLI invocation never
// constructs one: it makes at most a couple of Broker calls before the
// process exits, so there is nothing to amortise, and Resolve/OpenVault
// above stay the always-fresh default for it and every other caller.
//
// The idle window, not a per-item ACL check, is what keeps a cached key
// from silently outliving `cpass lock` or a rotated Keychain item: cpass
// ships CGO_ENABLED=0 by default (ADR-0007), so the Keychain reader this
// sits in front of (keychain_darwin.go's keychainGet) cannot tell a
// user-presence (Touch ID) item from a plain one — only whether the read
// itself succeeds, which is also the only signal a `security`(1) subprocess
// call ever gave `cpass` to begin with. Bounding every cached key to
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

// NewKeyCache returns a KeyCache whose key re-derives after idle with no
// calls. Pass DefaultIdleTimeout to match the Broker's own default.
func NewKeyCache(idle time.Duration) *KeyCache {
	return &KeyCache{idle: idle}
}

// Key returns the cached key if one was fetched within the idle window,
// re-deriving it through UnlockKey() otherwise. Every call, hit or miss,
// slides the window forward from now — the same way the Broker process's
// own Accept deadline resets on every request (process_unix.go's Serve) —
// so a cache that stays busy never re-derives, and one left alone re-checks
// UnlockKey() after idle: the bounded re-check that keeps `cpass lock` (on
// the Broker-socket path) or a changed/removed Keychain item from being
// silently ignored forever.
func (c *KeyCache) Key() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key != nil && time.Since(c.at) < c.idle {
		c.at = time.Now()
		return c.key, nil
	}
	key, err := UnlockKey()
	if err != nil {
		c.key, c.at = nil, time.Time{}
		return nil, err
	}
	c.key, c.at = key, time.Now()
	return key, nil
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
	return resolveFromVault(v, refs)
}
