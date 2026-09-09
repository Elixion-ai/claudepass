//go:build e2e

package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
)

// EnvTestPublicKey lets e2e tests trust a throwaway keypair instead of the
// embedded production key, so a test can mint its own tokens without ever
// touching the real private key — which does not live in this repo at all
// (see cmd/keygen). Reading it happens only in binaries built with -tags
// e2e; a release binary has no way to swap the trusted key.
const EnvTestPublicKey = "CPASS_TEST_LICENSE_PUBKEY"

func init() {
	s := os.Getenv(EnvTestPublicKey)
	if s == "" {
		return
	}
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(k) != ed25519.PublicKeySize {
		panic("license: " + EnvTestPublicKey + " must be base64 of a 32-byte Ed25519 public key")
	}
	trustedPublicKey = k
}
