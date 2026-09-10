//go:build !(darwin && touchid && cgo)

package broker

// touchIDBuildSupported is false in every build except darwin with
// -tags touchid and cgo enabled — see touchid_darwin.go, the only other
// file that defines this constant (the two build constraints are exact
// complements, so exactly one of the two files compiles).
const touchIDBuildSupported = false

// keychainSetUserPresence and keychainGetUserPresence are unreachable in
// this build: TouchIDAvailable() is always false here, so nothing calls
// them outside their own package (cli checks TouchIDAvailable() first).
// They exist, returning ErrTouchIDUnsupported, so the broker package (and
// the cli commands that opt into Touch ID) build in every configuration,
// including the CGO_ENABLED=0 release build this issue must leave
// unchanged.
func keychainSetUserPresence(service, account string, key []byte) error {
	return ErrTouchIDUnsupported
}

func keychainGetUserPresence(service, account string) ([]byte, error) {
	return nil, ErrTouchIDUnsupported
}
