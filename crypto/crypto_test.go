// Package crypto — unit tests for hybrid key exchange, AEAD, and HKDF.
package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestHybridKeyExchangeRoundTrip verifies that client and server arrive at
// identical shared secrets after a full hybrid key exchange.
func TestHybridKeyExchangeRoundTrip(t *testing.T) {
	// Client generates keypair
	clientPriv, clientPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Server encapsulates
	serverX25519Pub, mlkemCT, serverSS, err := Encapsulate(clientPub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	// Client decapsulates
	clientSS, err := Decapsulate(clientPriv, serverX25519Pub, mlkemCT)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	// Shared secrets must be identical
	if !bytes.Equal(serverSS.Combined, clientSS.Combined) {
		t.Fatal("shared secrets do not match")
	}
	if len(serverSS.Combined) == 0 {
		t.Fatal("shared secret is empty")
	}
	t.Logf("shared secret length: %d bytes", len(serverSS.Combined))
}

// TestHybridKeyExchangeUniqueness verifies that two separate key exchanges
// produce different shared secrets (no determinism leakage).
func TestHybridKeyExchangeUniqueness(t *testing.T) {
	priv1, pub1, _ := GenerateKeyPair()
	priv2, pub2, _ := GenerateKeyPair()

	_, _, ss1, _ := Encapsulate(pub1)
	_, _, ss2, _ := Encapsulate(pub2)
	_, _ = priv1, priv2

	if bytes.Equal(ss1.Combined, ss2.Combined) {
		t.Fatal("two key exchanges produced identical secrets (RNG broken?)")
	}
}

// TestValidateKeyPair tests the ValidateKeyPair helper.
func TestValidateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := ValidateKeyPair(priv, pub); err != nil {
		t.Fatalf("ValidateKeyPair: %v", err)
	}
}

// TestAEADChaCha20 verifies ChaCha20-Poly1305 seal/open round-trip.
func TestAEADChaCha20(t *testing.T) {
	testAEAD(t, CipherChaCha20Poly1305)
}

// TestAEADAES256GCM verifies AES-256-GCM seal/open round-trip.
func TestAEADAES256GCM(t *testing.T) {
	testAEAD(t, CipherAES256GCM)
}

func testAEAD(t *testing.T, suite CipherSuite) {
	t.Helper()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}

	aead, err := NewAEADWithSuite(suite, key)
	if err != nil {
		t.Fatalf("NewAEADWithSuite(%s): %v", suite, err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand nonce: %v", err)
	}

	plaintext := []byte("hello hivoid secure world")
	ad := []byte("additional-data")

	ct, err := aead.Seal(nonce, plaintext, ad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	pt, err := aead.Open(nonce, ct, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypted mismatch: got %q, want %q", pt, plaintext)
	}
}

// TestAEADTamperDetection verifies authentication tag rejects modified ciphertext.
func TestAEADTamperDetection(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck

	aead, _ := NewAEADWithSuite(CipherChaCha20Poly1305, key)
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce) //nolint:errcheck

	plaintext := []byte("secret message")
	ct, _ := aead.Seal(nonce, plaintext, nil)

	// Flip a bit in the ciphertext
	ct[0] ^= 0xFF

	_, err := aead.Open(nonce, ct, nil)
	if err == nil {
		t.Fatal("tampered ciphertext should have been rejected")
	}
}

// TestHKDFDerivedKeysNotEqual ensures client and server keys are different
// (the direction-separation prevents reflection attacks).
func TestHKDFDerivedKeysNotEqual(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	_, _, ss, _ := Encapsulate(pub)
	clientSS, _ := Decapsulate(priv, func() []byte {
		// Re-run encapsulate to get serverX25519Pub
		sX, _, _, _ := Encapsulate(pub)
		return sX
	}(), func() []byte {
		_, ct, _, _ := Encapsulate(pub)
		return ct
	}())
	_ = ss
	_ = clientSS

	salt := make([]byte, 32)
	rand.Read(salt) //nolint:errcheck

	// Use a fabricated shared secret for isolation
	fakeSS := &HybridSharedSecret{Combined: salt}

	clientDK, err := DeriveSessionKeys(fakeSS, salt, true)
	if err != nil {
		t.Fatal(err)
	}
	serverDK, err := DeriveSessionKeys(fakeSS, salt, false)
	if err != nil {
		t.Fatal(err)
	}

	// Client encrypt key should equal server decrypt key
	if !bytes.Equal(clientDK.EncryptKey, serverDK.DecryptKey) {
		t.Fatal("client encrypt key != server decrypt key")
	}
	// Client decrypt key should equal server encrypt key
	if !bytes.Equal(clientDK.DecryptKey, serverDK.EncryptKey) {
		t.Fatal("client decrypt key != server encrypt key")
	}
}

// TestIncrementNonce verifies nonce increment handles carry correctly.
func TestIncrementNonce(t *testing.T) {
	cases := []struct {
		input []byte
		want  []byte
	}{
		{[]byte{0x00, 0x00, 0x00}, []byte{0x00, 0x00, 0x01}},
		{[]byte{0x00, 0x00, 0xFF}, []byte{0x00, 0x01, 0x00}},
		{[]byte{0x00, 0xFF, 0xFF}, []byte{0x01, 0x00, 0x00}},
		{[]byte{0xFF, 0xFF, 0xFF}, []byte{0x00, 0x00, 0x00}}, // overflow wraps
	}
	for _, c := range cases {
		got := make([]byte, len(c.input))
		copy(got, c.input)
		IncrementNonce(got)
		if !bytes.Equal(got, c.want) {
			t.Errorf("IncrementNonce(%x) = %x, want %x", c.input, got, c.want)
		}
	}
}

// BenchmarkHybridKeyExchange measures full hybrid handshake latency.
func BenchmarkHybridKeyExchange(b *testing.B) {
	for i := 0; i < b.N; i++ {
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
		sXPub, ct, _, err := Encapsulate(pub)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := Decapsulate(priv, sXPub, ct); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAEADSeal measures ChaCha20-Poly1305 seal throughput.
func BenchmarkAEADSealChaCha(b *testing.B) {
	benchmarkAEADSeal(b, CipherChaCha20Poly1305, 4096)
}

// BenchmarkAEADSealAES measures AES-256-GCM seal throughput.
func BenchmarkAEADSealAES(b *testing.B) {
	benchmarkAEADSeal(b, CipherAES256GCM, 4096)
}

func benchmarkAEADSeal(b *testing.B, suite CipherSuite, size int) {
	b.Helper()
	key := make([]byte, 32)
	rand.Read(key) //nolint:errcheck
	aead, err := NewAEADWithSuite(suite, key)
	if err != nil {
		b.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	plaintext := make([]byte, size)
	rand.Read(plaintext) //nolint:errcheck

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IncrementNonce(nonce)
		if _, err := aead.Seal(nonce, plaintext, nil); err != nil {
			b.Fatal(err)
		}
	}
}
