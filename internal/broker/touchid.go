package broker

import "errors"

// ErrTouchIDUnsupported is returned by SetKeychainKeyUserPresence and
// GetKeychainKeyUserPresence when this binary was not built with Touch ID /
// user-presence Keychain support: -tags touchid, on darwin, with cgo
// enabled (CGO_ENABLED=1). A release binary (CGO_ENABLED=0, the default
// per ADR-0007 and the constraint this issue must not disturb) always
// returns this — it links no Security framework and can set no
// SecAccessControl.
var ErrTouchIDUnsupported = errors.New("broker: this cpass binary was not built with Touch ID Keychain support (rebuild with -tags touchid on macOS with cgo enabled, CGO_ENABLED=1; see docs/SECURITY.md)")

// TouchIDAvailable reports whether this binary was built with Touch ID /
// user-presence Keychain support. False in every CGO_ENABLED=0 build,
// which includes every release build and the default `go build`/`go test`
// invocation — this only ever reports true in a binary deliberately built
// with `-tags touchid` on darwin with cgo enabled.
func TouchIDAvailable() bool { return touchIDBuildSupported }

// SetKeychainKeyUserPresence stores key in the Keychain under this Vault's
// account (service, account — same identity SetKeychainKey uses) with a
// SecAccessControl requiring kSecAccessControlUserPresence: Touch ID or
// the device passcode. It replaces any existing item under that identity,
// including a plain, no-ACL item from a previous `cpass init` or `cpass
// keychain upgrade` run without --touch-id — that is exactly what `cpass
// keychain upgrade --touch-id` uses this for.
//
// The stored bytes are base64-encoded exactly like SetKeychainKey's, so
// the ordinary, cgo-free keychainGet in keychain_darwin.go — the function
// broker.UnlockKey() calls on every invocation, unconditionally, in every
// build — reads this item back unchanged. Nothing about UnlockKey()'s own
// code path changes: it is the Keychain itself, not cpass, that then
// prompts for Touch ID or the passcode on that read, because the ACL is a
// property of the item, enforced by the OS for any reader. See
// docs/SECURITY.md.
//
// macOS + -tags touchid + cgo only; returns ErrTouchIDUnsupported in every
// other build.
func SetKeychainKeyUserPresence(key []byte) error {
	return keychainSetUserPresence(KeychainService(), keychainAccount(), key)
}

// GetKeychainKeyUserPresence reads the Keychain item back via
// SecItemCopyMatching, prompting for Touch ID or the device passcode if
// the item's SecAccessControl requires it (which it does for any item
// SetKeychainKeyUserPresence created). It is not on cpass's normal
// UnlockKey() path — see SetKeychainKeyUserPresence's doc comment above —
// it exists for tooling and the manual verification checklist in
// docs/SECURITY.md, which is the only place a real cpass invocation should
// ever trigger the Keychain's access-control GUI.
//
// macOS + -tags touchid + cgo only; returns ErrTouchIDUnsupported in every
// other build.
func GetKeychainKeyUserPresence() ([]byte, error) {
	return keychainGetUserPresence(KeychainService(), keychainAccount())
}
