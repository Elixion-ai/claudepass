package vault

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the size in bytes of both the unlock key and the data key.
const KeySize = chacha20poly1305.KeySize

// ErrWrongKey is returned when the unlock key cannot unwrap the data key.
var ErrWrongKey = errors.New("vault: wrong key")

// ErrTampered is returned when the Vault body fails its integrity check.
var ErrTampered = errors.New("vault: integrity check failed (file is tampered or corrupt)")

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("vault: entropy: %w", err)
	}
	return b, nil
}

// seal encrypts plaintext with key using XChaCha20-Poly1305 and a fresh nonce.
func seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = randomBytes(aead.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

func open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("vault: bad nonce length")
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}
