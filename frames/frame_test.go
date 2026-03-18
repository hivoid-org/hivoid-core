// Package frames — unit tests for frame encoding/decoding.
package frames

import (
	"bytes"
	"io"
	"testing"
)

// TestFrameEncodeDecodeRoundTrip verifies that a frame survives encode→decode.
func TestFrameEncodeDecodeRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		ft      FrameType
		flags   FrameFlag
		payload []byte
	}{
		{"data frame", FrameData, FlagEncrypted, []byte("hello world payload")},
		{"control frame empty", FrameControl, 0, nil},
		{"rekey frame", FrameRekey, 0, []byte{0x01, 0x02, 0x03, 0x04}},
		{"signal frame", FrameSignal, FlagPadded, bytes.Repeat([]byte{0xAB}, 100)},
		{"ping", FramePing, 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := &Frame{Type: tc.ft, Flags: tc.flags, Payload: tc.payload}
			encoded := orig.Encode()

			decoded, err := Decode(bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}

			if decoded.Type != orig.Type {
				t.Errorf("type: got %d, want %d", decoded.Type, orig.Type)
			}
			if decoded.Flags != orig.Flags {
				t.Errorf("flags: got %d, want %d", decoded.Flags, orig.Flags)
			}
			if !bytes.Equal(decoded.Payload, orig.Payload) {
				t.Errorf("payload mismatch")
			}
		})
	}
}

// TestFrameHeaderSize verifies the encoded frame has the correct header size.
func TestFrameHeaderSize(t *testing.T) {
	f := &Frame{Type: FrameData, Payload: []byte("test")}
	encoded := f.Encode()
	if len(encoded) != HeaderSize+len(f.Payload) {
		t.Errorf("encoded length: got %d, want %d", len(encoded), HeaderSize+len(f.Payload))
	}
}

// TestDecodeEOF verifies that Decode returns io.EOF on empty reader.
func TestDecodeEOF(t *testing.T) {
	_, err := Decode(bytes.NewReader(nil))
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

// TestDecodeOversizedFrame verifies that oversized payloads are rejected.
func TestDecodeOversizedFrame(t *testing.T) {
	// Construct a header claiming a 5MB payload (> MaxPayloadSize)
	header := make([]byte, HeaderSize)
	header[0] = byte(FrameData)
	header[1] = 0
	// 5 MB in big-endian uint32
	header[2] = 0x00
	header[3] = 0x50
	header[4] = 0x00
	header[5] = 0x00

	_, err := Decode(bytes.NewReader(header))
	if err == nil {
		t.Fatal("expected error for oversized frame, got nil")
	}
}

// TestFrameFlagHelpers verifies HasFlag and SetFlag.
func TestFrameFlagHelpers(t *testing.T) {
	f := &Frame{}
	if f.HasFlag(FlagEncrypted) {
		t.Fatal("should not have encrypted flag")
	}
	f.SetFlag(FlagEncrypted)
	if !f.HasFlag(FlagEncrypted) {
		t.Fatal("should have encrypted flag after SetFlag")
	}
	f.SetFlag(FlagPadded)
	if !f.HasFlag(FlagPadded) || !f.HasFlag(FlagEncrypted) {
		t.Fatal("both flags should be set")
	}
}

type shortWriter struct {
	w        io.Writer
	maxChunk int
}

func (s shortWriter) Write(p []byte) (int, error) {
	if len(p) > s.maxChunk {
		p = p[:s.maxChunk]
	}
	return s.w.Write(p)
}

func TestFrameWriteToHandlesShortWrites(t *testing.T) {
	f := &Frame{Type: FrameData, Flags: FlagEncrypted, Payload: bytes.Repeat([]byte{0xAB}, 1024)}
	var buf bytes.Buffer
	n, err := f.WriteTo(shortWriter{w: &buf, maxChunk: 17})
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if int(n) != HeaderSize+len(f.Payload) {
		t.Fatalf("WriteTo bytes: got %d want %d", n, HeaderSize+len(f.Payload))
	}
	if !bytes.Equal(buf.Bytes(), f.Encode()) {
		t.Fatal("encoded output mismatch")
	}
}

// TestClientHelloEncodeDecodeRoundTrip tests the ClientHello message codec.
func TestClientHelloEncodeDecodeRoundTrip(t *testing.T) {
	var h ClientHello
	h.Version = 1
	for i := range h.SessionSalt {
		h.SessionSalt[i] = byte(i)
	}
	for i := range h.X25519PublicKey {
		h.X25519PublicKey[i] = byte(i + 100)
	}
	for i := range h.MLKEMEncapKey {
		h.MLKEMEncapKey[i] = byte(i % 256)
	}

	encoded := h.Encode()
	decoded, err := DecodeClientHello(encoded)
	if err != nil {
		t.Fatalf("DecodeClientHello: %v", err)
	}
	if decoded.Version != h.Version {
		t.Errorf("version mismatch: %d != %d", decoded.Version, h.Version)
	}
	if decoded.SessionSalt != h.SessionSalt {
		t.Error("session salt mismatch")
	}
	if decoded.X25519PublicKey != h.X25519PublicKey {
		t.Error("x25519 key mismatch")
	}
	if decoded.MLKEMEncapKey != h.MLKEMEncapKey {
		t.Error("mlkem key mismatch")
	}
}

// TestServerHelloEncodeDecodeRoundTrip tests the ServerHello message codec.
func TestServerHelloEncodeDecodeRoundTrip(t *testing.T) {
	var h ServerHello
	h.Version = 1
	for i := range h.X25519PublicKey {
		h.X25519PublicKey[i] = byte(i)
	}
	for i := range h.MLKEMCiphertext {
		h.MLKEMCiphertext[i] = byte(i % 128)
	}

	encoded := h.Encode()
	decoded, err := DecodeServerHello(encoded)
	if err != nil {
		t.Fatalf("DecodeServerHello: %v", err)
	}
	if decoded.X25519PublicKey != h.X25519PublicKey {
		t.Error("x25519 key mismatch")
	}
	if decoded.MLKEMCiphertext != h.MLKEMCiphertext {
		t.Error("mlkem ciphertext mismatch")
	}
}

// TestRekeyPayloadRoundTrip tests rekey payload codec.
func TestRekeyPayloadRoundTrip(t *testing.T) {
	rp := &RekeyPayload{SeqNum: 42}
	for i := range rp.NewSalt {
		rp.NewSalt[i] = byte(i)
	}
	encoded := rp.Encode()
	decoded, err := DecodeRekeyPayload(encoded)
	if err != nil {
		t.Fatalf("DecodeRekeyPayload: %v", err)
	}
	if decoded.SeqNum != rp.SeqNum {
		t.Errorf("SeqNum: %d != %d", decoded.SeqNum, rp.SeqNum)
	}
	if decoded.NewSalt != rp.NewSalt {
		t.Error("NewSalt mismatch")
	}
}

// BenchmarkFrameEncode benchmarks frame encoding.
func BenchmarkFrameEncode(b *testing.B) {
	payload := bytes.Repeat([]byte{0xAB}, 1024)
	f := &Frame{Type: FrameData, Flags: FlagEncrypted, Payload: payload}
	b.SetBytes(int64(HeaderSize + len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.Encode()
	}
}

// BenchmarkFrameDecode benchmarks frame decoding.
func BenchmarkFrameDecode(b *testing.B) {
	payload := bytes.Repeat([]byte{0xAB}, 1024)
	f := &Frame{Type: FrameData, Flags: FlagEncrypted, Payload: payload}
	encoded := f.Encode()
	b.SetBytes(int64(len(encoded)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decode(bytes.NewReader(encoded))
		if err != nil {
			b.Fatal(err)
		}
	}
}
