// Command keygen generates the Ed25519 keypair ClaudePass uses to sign and
// verify license tokens.
//
// Run it once:
//
//	go run ./internal/license/cmd/keygen
//
// Paste the printed public key into the PublicKeyBase64 constant in
// internal/license/publickey.go and commit that file — it is the only half
// that belongs in this repository. Store the printed private key OUTSIDE
// this repository, in the license-issuing service's own secret store (the
// small hosted service from ADR-0006 that mints tokens after checkout); it
// must never be committed, logged, or held by the cpass binary itself,
// which only ever verifies. If the private key is ever lost or exposed,
// generate a new pair, ship the new public key in a release, and re-issue
// tokens to active subscribers; existing tokens signed by the old key stop
// verifying at that point.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	fmt.Println("public key — commit this into internal/license/publickey.go:")
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	fmt.Println()
	fmt.Println("private key — KEEP OUT OF THIS REPO. Store it only in the license service's secret store:")
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
}
