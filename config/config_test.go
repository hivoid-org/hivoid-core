package config

import (
	"os"
	"path/filepath"
	"testing"
)

const testUUID = "550e8400-e29b-41d4-a716-446655440000"

// minimalURI builds the simplest valid hivoid:// URI.
func minimalURI() string {
	return "hivoid://" + testUUID + "@vpn.example.com:443"
}

// ---------------------------------------------------------------------------
// ParseURI tests
// ---------------------------------------------------------------------------

func TestParseURIMinimal(t *testing.T) {
	cfg, err := ParseURI(minimalURI())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.UUID != testUUID {
		t.Errorf("uuid = %q; want %q", cfg.UUID, testUUID)
	}
	if cfg.Server != "vpn.example.com" {
		t.Errorf("server = %q; want vpn.example.com", cfg.Server)
	}
	if cfg.Port != 443 {
		t.Errorf("port = %d; want 443", cfg.Port)
	}
	// Defaults should be applied.
	if cfg.Mode != DefaultMode {
		t.Errorf("mode = %q; want %q", cfg.Mode, DefaultMode)
	}
	if cfg.SocksPort != DefaultSocksPort {
		t.Errorf("socks_port = %d; want %d", cfg.SocksPort, DefaultSocksPort)
	}
}

func TestParseURIFull(t *testing.T) {
	raw := "hivoid://" + testUUID + "@vpn.example.com:8443" +
		"?mode=stealth&obfs=random&socks-port=9999&dns-port=5353&insecure=true" +
		"#Home"
	cfg, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != "stealth" {
		t.Errorf("mode = %q; want stealth", cfg.Mode)
	}
	if cfg.Obfs != "random" {
		t.Errorf("obfs = %q; want random", cfg.Obfs)
	}
	if cfg.SocksPort != 9999 {
		t.Errorf("socks_port = %d; want 9999", cfg.SocksPort)
	}
	if cfg.DNSPort != 5353 {
		t.Errorf("dns_port = %d; want 5353", cfg.DNSPort)
	}
	if !cfg.Insecure {
		t.Error("insecure should be true")
	}
	if cfg.Name != "Home" {
		t.Errorf("name = %q; want Home", cfg.Name)
	}
}

func TestParseURIRoundTrip(t *testing.T) {
	original, err := ParseURI(minimalURI())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	uri := original.URI()
	roundtripped, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("parse roundtrip: %v", err)
	}
	if roundtripped.UUID != original.UUID {
		t.Errorf("uuid mismatch: %q vs %q", roundtripped.UUID, original.UUID)
	}
	if roundtripped.Server != original.Server {
		t.Errorf("server mismatch: %q vs %q", roundtripped.Server, original.Server)
	}
	if roundtripped.Port != original.Port {
		t.Errorf("port mismatch: %d vs %d", roundtripped.Port, original.Port)
	}
	if roundtripped.Mode != original.Mode {
		t.Errorf("mode mismatch: %q vs %q", roundtripped.Mode, original.Mode)
	}
}

func TestParseURIInvalidScheme(t *testing.T) {
	_, err := ParseURI("vless://" + testUUID + "@host:443")
	if err == nil {
		t.Fatal("expected error for wrong scheme, got nil")
	}
}

func TestParseURIInvalidUUID(t *testing.T) {
	_, err := ParseURI("hivoid://not-a-uuid@host:443")
	if err == nil {
		t.Fatal("expected error for invalid UUID, got nil")
	}
}

func TestParseURIInvalidPort(t *testing.T) {
	_, err := ParseURI("hivoid://" + testUUID + "@host:99999")
	if err == nil {
		t.Fatal("expected error for port out of range, got nil")
	}
}

func TestParseURIMissingHost(t *testing.T) {
	_, err := ParseURI("hivoid://" + testUUID + "@:443")
	if err == nil {
		t.Fatal("expected error for missing host, got nil")
	}
}

// ---------------------------------------------------------------------------
// Validate tests
// ---------------------------------------------------------------------------

func TestValidateMissingUUID(t *testing.T) {
	c := &Config{Server: "example.com", Port: 443}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing UUID, got nil")
	}
}

func TestValidateMissingServer(t *testing.T) {
	c := &Config{UUID: testUUID, Port: 443}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing server, got nil")
	}
}

func TestValidatePortZero(t *testing.T) {
	c := &Config{UUID: testUUID, Server: "example.com", Port: 0}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for port 0, got nil")
	}
}

func TestValidatePortTooLarge(t *testing.T) {
	c := &Config{UUID: testUUID, Server: "example.com", Port: 65536}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for port 65536, got nil")
	}
}

func TestValidateUnknownMode(t *testing.T) {
	c := &Config{UUID: testUUID, Server: "example.com", Port: 443, Mode: "turbo"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for unknown mode, got nil")
	}
}

func TestValidateUnknownObfs(t *testing.T) {
	c := &Config{UUID: testUUID, Server: "example.com", Port: 443, Mode: DefaultMode, Obfs: "xor"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for unknown obfs, got nil")
	}
}

func TestValidateBadCertPin(t *testing.T) {
	c := &Config{UUID: testUUID, Server: "example.com", Port: 443, Mode: DefaultMode, CertPin: "tooshort"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for cert_pin wrong length, got nil")
	}
}

func TestValidateGood(t *testing.T) {
	c := &Config{UUID: testUUID, Server: "example.com", Port: 443}
	c.withDefaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// JSON round-trip test
// ---------------------------------------------------------------------------

func TestLoadJSONRoundTrip(t *testing.T) {
	original := &Config{
		UUID:        testUUID,
		Server:      "vpn.example.com",
		Port:        8443,
		Mode:        "stealth",
		Obfs:        "random",
		SocksPort:   9090,
		DNSPort:     5353,
		DNSUpstream: "1.1.1.1:53",
		Insecure:    true,
		Name:        "TestProfile",
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	if err := original.SaveJSON(path); err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}

	loaded, err := LoadJSON(path)
	if err != nil {
		t.Fatalf("LoadJSON: %v", err)
	}

	if *loaded != *original {
		t.Errorf("round-trip mismatch:\ngot  %+v\nwant %+v", *loaded, *original)
	}
}

func TestLoadJSONMissingFile(t *testing.T) {
	_, err := LoadJSON(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadJSONInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadJSON(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// ---------------------------------------------------------------------------
// UUIDBytes test
// ---------------------------------------------------------------------------

func TestUUIDBytes(t *testing.T) {
	c := &Config{UUID: testUUID}
	b, err := c.UUIDBytes()
	if err != nil {
		t.Fatalf("UUIDBytes: %v", err)
	}
	// testUUID "550e8400-e29b-41d4-a716-446655440000"
	// First byte: 0x55
	if b[0] != 0x55 {
		t.Errorf("b[0] = %#x; want 0x55", b[0])
	}
	// bytes 1–3: 0x0e, 0x84, 0x00
	if b[1] != 0x0e || b[2] != 0x84 || b[3] != 0x00 {
		t.Errorf("unexpected bytes: %x", b[:4])
	}
}

func TestUUIDBytesInvalid(t *testing.T) {
	c := &Config{UUID: "not-a-uuid"}
	_, err := c.UUIDBytes()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
