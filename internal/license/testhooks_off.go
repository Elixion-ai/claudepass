//go:build !e2e

package license

// No test hooks in release builds: the trusted public key is fixed to
// PublicKeyBase64.
