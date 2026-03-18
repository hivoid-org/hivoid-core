// Package crypto — HKDF-based key derivation utilities.
// All session keys are derived from the hybrid shared secret
// using HKDF-SHA256 with domain-separated labels.
package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// LabelSessionKey is used to derive the AEAD session encryption key.
	LabelSessionKey = "hivoid-session-key"
	// LabelSessionIV is used to derive the initial nonce/IV.
	LabelSessionIV = "hivoid-session-iv"
	// LabelRekeyKey is used during key rotation.
	LabelRekeyKey = "hivoid-rekey-key"
	// LabelRekeyIV is used during key rotation for the new IV.
	LabelRekeyIV = "hivoid-rekey-iv"
)

// DerivedKeys holds session keys derived from the hybrid shared secret.
type DerivedKeys struct {
	// EncryptKey is the AEAD key for encrypting outbound data (32 bytes).
	EncryptKey []byte
	// DecryptKey is the AEAD key for decrypting inbound data (32 bytes).
	DecryptKey []byte
	// SendNonce is the initial nonce for outbound records (12 bytes).
	SendNonce []byte
	// RecvNonce is the initial nonce for inbound records (12 bytes).
	RecvNonce []byte

	// Suite is the negotiated cipher suite.
	Suite CipherSuite
}

// DeriveSessionKeys derives all session keys from the hybrid shared secret.
// salt is a fresh random value exchanged during the handshake (nonces).
// isClient determines key assignment direction (prevents reflection attacks).
func DeriveSessionKeys(sharedSecret *HybridSharedSecret, salt []byte, isClient bool) (*DerivedKeys, error) {
	suite := CipherChaCha20Poly1305
	if HasAESNI() {
		suite = CipherAES256GCM
	}

	// Derive client→server key
	clientKey, err := deriveKey(sharedSecret.Combined, salt, LabelSessionKey+"-c2s", 32)
	if err != nil {
		return nil, fmt.Errorf("derive client key: %w", err)
	}

	// Derive server→client key
	serverKey, err := deriveKey(sharedSecret.Combined, salt, LabelSessionKey+"-s2c", 32)
	if err != nil {
		return nil, fmt.Errorf("derive server key: %w", err)
	}

	// Derive nonces (12 bytes for both ChaCha20Poly1305 and AES-GCM)
	clientNonce, err := deriveKey(sharedSecret.Combined, salt, LabelSessionIV+"-c2s", 12)
	if err != nil {
		return nil, fmt.Errorf("derive client nonce: %w", err)
	}
	serverNonce, err := deriveKey(sharedSecret.Combined, salt, LabelSessionIV+"-s2c", 12)
	if err != nil {
		return nil, fmt.Errorf("derive server nonce: %w", err)
	}

	dk := &DerivedKeys{Suite: suite}
	if isClient {
		// Client sends with clientKey, receives with serverKey
		dk.EncryptKey = clientKey
		dk.DecryptKey = serverKey
		dk.SendNonce = clientNonce
		dk.RecvNonce = serverNonce
	} else {
		// Server sends with serverKey, receives with clientKey
		dk.EncryptKey = serverKey
		dk.DecryptKey = clientKey
		dk.SendNonce = serverNonce
		dk.RecvNonce = clientNonce
	}

	return dk, nil
}

// DeriveRekeyMaterial derives new keys for a key rotation event.
// It uses the current session key as additional input for forward secrecy.
func DeriveRekeyMaterial(currentKey []byte, salt []byte, isClient bool) (*DerivedKeys, error) {
	// Use the current encryption key as part of the IKM for rekey
	// This provides a chain: each key depends on the previous one
	ikm := make([]byte, len(currentKey)+len(salt))
	copy(ikm, currentKey)
	copy(ikm[len(currentKey):], salt)

	fakeSS := &HybridSharedSecret{Combined: ikm}
	return DeriveSessionKeys(fakeSS, salt, isClient)
}

// deriveKey runs HKDF-SHA256 to produce keyLen bytes of key material.
// This is the core primitive used by all key derivation in HiVoid.
func deriveKey(secret, salt []byte, label string, keyLen int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(label))
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf expand (%s): %w", label, err)
	}
	return key, nil
}

// ZeroizeDerivedKeys securely wipes all key material.
func ZeroizeDerivedKeys(dk *DerivedKeys) {
	if dk == nil {
		return
	}
	Zeroize(dk.EncryptKey)
	Zeroize(dk.DecryptKey)
	Zeroize(dk.SendNonce)
	Zeroize(dk.RecvNonce)
}
