// Package license verifies ClaudePass license tokens entirely offline: no
// network call ever happens in this package, or anywhere in the CLI.
//
// A token is:
//
//	base64url(JSON{sub, plan, exp, iat, jti}) + "." + base64url(Ed25519 signature)
//
// where the signature covers the bytes of the first (already-encoded)
// segment, JWT-style, so verification never has to re-serialise JSON. The
// signing key lives only in the license-issuing service, outside this
// repository (see cmd/keygen); ClaudePass ships the public half and only
// ever verifies.
package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Plan names carried in a token's payload.
const (
	PlanFree = "free"
	PlanPro  = "pro"
)

// FreeSecretLimit is the number of Secrets the free plan holds.
const FreeSecretLimit = 3

// Payload is the signed body of a license token.
type Payload struct {
	Sub  string `json:"sub"`  // account email
	Plan string `json:"plan"` // e.g. "pro"
	Exp  int64  `json:"exp"`  // unix seconds
	Iat  int64  `json:"iat"`  // unix seconds
	JTI  string `json:"jti"`  // unique token id
}

// ErrMalformed is returned when a token string is not two dot-separated
// base64url segments carrying valid JSON.
var ErrMalformed = errors.New("license: malformed token")

// ErrSignature is returned when a token's signature does not verify against
// the trusted public key (a tampered or forged token).
var ErrSignature = errors.New("license: invalid signature")

var b64 = base64.RawURLEncoding

// Sign builds a token string for p, signed with priv. This is the
// license-issuing service's job, not ClaudePass's: nothing in the CLI calls
// it. It exists here so cmd/keygen and tests can mint tokens against the
// same format Verify checks.
func Sign(priv ed25519.PrivateKey, p Payload) (string, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	part1 := b64.EncodeToString(body)
	sig := ed25519.Sign(priv, []byte(part1))
	return part1 + "." + b64.EncodeToString(sig), nil
}

// Verify parses raw and checks its signature against the trusted public
// key. It does not consult the clock: an expired-but-validly-signed token
// verifies fine, and it is Load's job to decide what an expired Payload
// means for the caller.
func Verify(raw string) (Payload, error) {
	part1, part2, ok := strings.Cut(raw, ".")
	if !ok || part1 == "" || part2 == "" {
		return Payload{}, ErrMalformed
	}
	body, err := b64.DecodeString(part1)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	sig, err := b64.DecodeString(part2)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if !ed25519.Verify(trustedPublicKey, []byte(part1), sig) {
		return Payload{}, ErrSignature
	}
	var p Payload
	if err := json.Unmarshal(body, &p); err != nil {
		return Payload{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return p, nil
}
