// Package crypto — AEAD layer.
// Auto-selects ChaCha20-Poly1305 or AES-256-GCM based on CPU capabilities.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// CipherSuite identifies the selected AEAD algorithm.
type CipherSuite uint8

const (
	CipherChaCha20Poly1305 CipherSuite = iota
	CipherAES256GCM
)

func (c CipherSuite) String() string {
	switch c {
	case CipherChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	case CipherAES256GCM:
		return "AES-256-GCM"
	default:
		return "unknown"
	}
}

// AEAD wraps a cipher.AEAD with metadata about its suite and key.
type AEAD struct {
	suite  CipherSuite
	aead   cipher.AEAD
	keyLen int
}

// NewAEAD creates an AEAD instance. It auto-selects the cipher suite
// based on CPU hardware acceleration (detected via HasAESNI).
// The key must be exactly KeySize() bytes.
func NewAEAD(key []byte) (*AEAD, error) {
	if HasAESNI() {
		return newAES256GCM(key)
	}
	return newChaCha20Poly1305(key)
}

// NewAEADWithSuite creates an AEAD with an explicitly chosen cipher suite.
func NewAEADWithSuite(suite CipherSuite, key []byte) (*AEAD, error) {
	switch suite {
	case CipherChaCha20Poly1305:
		return newChaCha20Poly1305(key)
	case CipherAES256GCM:
		return newAES256GCM(key)
	default:
		return nil, fmt.Errorf("unknown cipher suite: %d", suite)
	}
}

func newChaCha20Poly1305(key []byte) (*AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("chacha20poly1305: key must be %d bytes, got %d",
			chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305.New: %w", err)
	}
	return &AEAD{suite: CipherChaCha20Poly1305, aead: aead, keyLen: chacha20poly1305.KeySize}, nil
}

func newAES256GCM(key []byte) (*AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("aes-256-gcm: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return &AEAD{suite: CipherAES256GCM, aead: aead, keyLen: 32}, nil
}

// Suite returns the active cipher suite.
func (a *AEAD) Suite() CipherSuite { return a.suite }

// NonceSize returns the required nonce length for this AEAD.
func (a *AEAD) NonceSize() int { return a.aead.NonceSize() }

// KeySize returns the required key length in bytes.
func (a *AEAD) KeySize() int { return a.keyLen }

// Overhead returns the authentication tag overhead in bytes.
func (a *AEAD) Overhead() int { return a.aead.Overhead() }

// Seal encrypts and authenticates plaintext with the given nonce and additional data.
// nonce must be exactly NonceSize() bytes.
// Returns ciphertext + authentication tag appended together.
func (a *AEAD) Seal(nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.aead.NonceSize() {
		return nil, fmt.Errorf("seal: nonce must be %d bytes, got %d",
			a.aead.NonceSize(), len(nonce))
	}
	ct := a.aead.Seal(nil, nonce, plaintext, additionalData)
	return ct, nil
}

// Open decrypts and verifies ciphertext. Returns plaintext on success.
func (a *AEAD) Open(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.aead.NonceSize() {
		return nil, fmt.Errorf("open: nonce must be %d bytes, got %d",
			a.aead.NonceSize(), len(nonce))
	}
	pt, err := a.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, errors.New("aead: authentication failed (tampered or corrupted data)")
	}
	return pt, nil
}

// IncrementNonce increments a big-endian nonce by 1.
// This is used for stream-based nonce management (per-record counter).
func IncrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i-- {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}
