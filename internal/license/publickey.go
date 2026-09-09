package license

import (
	"crypto/ed25519"
	"encoding/base64"
)

// PublicKeyBase64 is the Ed25519 public key ClaudePass trusts to verify
// license tokens offline. Generated once with `go run
// ./internal/license/cmd/keygen`; the matching private key is not in this
// repository — see that command's doc comment for where it lives.
const PublicKeyBase64 = "xzVpCa8P1lBh7U27rQdCJvw7341XBB0E+xvVirQEx4o="

// trustedPublicKey is decoded from PublicKeyBase64 by this package-level
// var initializer, which the Go spec guarantees runs before any init()
// function — including the e2e-only test override in testhooks_on.go, which
// runs after and may replace it for a test binary only.
var trustedPublicKey = mustDecodePublicKey(PublicKeyBase64)

func mustDecodePublicKey(s string) ed25519.PublicKey {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic("license: embedded public key is not valid base64: " + err.Error())
	}
	if len(k) != ed25519.PublicKeySize {
		panic("license: embedded public key has the wrong length")
	}
	return ed25519.PublicKey(k)
}
