// Package crypto implements the HiVoid hybrid cryptographic layer.
// It combines classical X25519 Diffie-Hellman with post-quantum ML-KEM-768
// (from the Go standard library's crypto/mlkem, NIST FIPS 203) to provide
// security against both classical and quantum adversaries.
// This protects against "harvest now, decrypt later" attacks.
package crypto

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
)

// ML-KEM-768 fixed sizes (NIST FIPS 203).
const (
	MLKEMEncapKeySize    = 1184 // encapsulation (public) key bytes
	MLKEMCiphertextSize  = 1088 // ciphertext bytes
)

// HybridPrivateKey holds both the classical and post-quantum private keys.
// Only the initiator (client) side generates the ML-KEM decapsulation key.
type HybridPrivateKey struct {
	// Classical: X25519 ephemeral private key
	X25519Private *ecdh.PrivateKey

	// Post-quantum: ML-KEM-768 decapsulation key (a.k.a. secret key)
	MLKEMDecapKey *mlkem.DecapsulationKey768
}

// HybridPublicKey holds the public components sent during key exchange.
type HybridPublicKey struct {
	// Classical: X25519 ephemeral public key (32 bytes)
	X25519Public []byte

	// Post-quantum: ML-KEM-768 encapsulation key (1184 bytes)
	MLKEMEncapKey []byte
}

// HybridSharedSecret is the result of the hybrid key exchange.
// It must be passed to HKDF to derive actual session keys.
type HybridSharedSecret struct {
	// Combined entropy from both key exchanges (SHA-512 of concatenation)
	Combined []byte
}

// GenerateKeyPair generates a new X25519 + ML-KEM-768 keypair for the initiator.
// The returned public key is sent to the responder (server) in the ClientHello.
func GenerateKeyPair() (*HybridPrivateKey, *HybridPublicKey, error) {
	// Generate X25519 ephemeral keypair
	x25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519 keygen: %w", err)
	}

	// Generate ML-KEM-768 keypair (crypto/mlkem, no rand.Reader needed — uses rand.Reader internally)
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, fmt.Errorf("mlkem keygen: %w", err)
	}

	priv := &HybridPrivateKey{
		X25519Private: x25519Priv,
		MLKEMDecapKey: dk,
	}
	pub := &HybridPublicKey{
		X25519Public:  x25519Priv.PublicKey().Bytes(),
		MLKEMEncapKey: dk.EncapsulationKey().Bytes(),
	}
	return priv, pub, nil
}

// Encapsulate is called by the responder (server) when it receives the client's public key.
// It performs both key exchanges and returns:
//   - The server's X25519 public key bytes (sent back in ServerHello)
//   - The ML-KEM ciphertext bytes (sent back in ServerHello)
//   - The shared secret derived from both exchanges
func Encapsulate(clientPub *HybridPublicKey) (serverX25519Pub []byte, mlkemCT []byte, ss *HybridSharedSecret, err error) {
	// --- X25519 ---
	serverX25519Priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("x25519 keygen (server): %w", err)
	}

	clientX25519Pub, err := ecdh.X25519().NewPublicKey(clientPub.X25519Public)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse client x25519 pubkey: %w", err)
	}

	x25519SS, err := serverX25519Priv.ECDH(clientX25519Pub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("x25519 ecdh: %w", err)
	}

	// --- ML-KEM-768 ---
	mlkemEK, err := mlkem.NewEncapsulationKey768(clientPub.MLKEMEncapKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse mlkem encap key: %w", err)
	}

	// Encapsulate returns (sharedKey, ciphertext) — stdlib order
	mlkemSS, ct := mlkemEK.Encapsulate()

	combined := combineSecrets(x25519SS, mlkemSS)

	return serverX25519Priv.PublicKey().Bytes(), ct, &HybridSharedSecret{Combined: combined}, nil
}

// Decapsulate is called by the initiator (client) after receiving the ServerHello.
// It uses the previously generated private keys to derive the matching shared secret.
func Decapsulate(priv *HybridPrivateKey, serverX25519Pub []byte, mlkemCT []byte) (*HybridSharedSecret, error) {
	// --- X25519 ---
	serverPub, err := ecdh.X25519().NewPublicKey(serverX25519Pub)
	if err != nil {
		return nil, fmt.Errorf("parse server x25519 pubkey: %w", err)
	}

	x25519SS, err := priv.X25519Private.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh (client): %w", err)
	}

	// --- ML-KEM-768 ---
	// Decapsulate returns (sharedKey []byte, err error) in crypto/mlkem
	mlkemSS, err := priv.MLKEMDecapKey.Decapsulate(mlkemCT)
	if err != nil {
		return nil, fmt.Errorf("mlkem decapsulate: %w", err)
	}

	combined := combineSecrets(x25519SS, mlkemSS)

	return &HybridSharedSecret{Combined: combined}, nil
}

// combineSecrets concatenates both shared secrets and hashes them together.
// Formula: SHA-512(x25519_ss || mlkem_ss) → 64 bytes of combined entropy.
// Using SHA-512 so there is enough IKM for HKDF to derive multiple keys.
func combineSecrets(x25519SS, mlkemSS []byte) []byte {
	h := sha512.New()
	h.Write(x25519SS)
	h.Write(mlkemSS)
	return h.Sum(nil)
}

// Zeroize securely wipes a byte slice to prevent secret leakage in memory.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ValidateKeyPair performs a full round-trip test to verify correctness.
// Used in unit tests; not for production code paths.
func ValidateKeyPair(clientPriv *HybridPrivateKey, clientPub *HybridPublicKey) error {
	serverX25519Pub, mlkemCT, serverSS, err := Encapsulate(clientPub)
	if err != nil {
		return fmt.Errorf("encapsulate: %w", err)
	}

	clientSS, err := Decapsulate(clientPriv, serverX25519Pub, mlkemCT)
	if err != nil {
		return fmt.Errorf("decapsulate: %w", err)
	}

	if len(serverSS.Combined) != len(clientSS.Combined) {
		return errors.New("shared secret length mismatch")
	}
	for i := range serverSS.Combined {
		if serverSS.Combined[i] != clientSS.Combined[i] {
			return fmt.Errorf("shared secret mismatch at byte %d", i)
		}
	}
	return nil
}

// RandomBytes generates n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Fingerprint returns a 4-byte hex fingerprint of a public key for logging.
func Fingerprint(pubKey []byte) string {
	h := sha256.Sum256(pubKey)
	return fmt.Sprintf("%x", h[:4])
}
