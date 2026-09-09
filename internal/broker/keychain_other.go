//go:build !darwin

package broker

import "errors"

var errKeychainUnsupported = errors.New("broker: the Keychain unlock source is macOS-only")

// keychainGet and keychainSet are unreachable in normal operation on this
// platform: UseKeychain() is always false here, so UnlockKey() and
// cpass init never call them. They exist so the broker package (and cli,
// which calls SetKeychainKey when UseKeychain() is true) builds everywhere.
func keychainGet(service, account string) ([]byte, error)   { return nil, errKeychainUnsupported }
func keychainSet(service, account string, key []byte) error { return errKeychainUnsupported }
