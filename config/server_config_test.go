package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerJSONNestedConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	data := `{
  "server": {
    "listen": ":4433",
    "mode": "PERFORMANCE",
    "log_level": "info"
  },
  "security": {
    "cert_file": "./cert.pem",
    "key_file": "./key.pem"
  },
  "features": {
    "hot_reload": true,
    "connection_tracking": true
  },
  "users": [
    {
      "uuid": "11111111-1111-1111-1111-111111111111",
      "email": "user1@example.com",
      "enabled": true,
      "max_connections": 2,
      "mode": "PERFORMANCE",
      "obfs": "none"
    }
  ]
}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerJSON(path)
	if err != nil {
		t.Fatalf("LoadServerJSON failed: %v", err)
	}
	if cfg.Listen() != ":4433" {
		t.Fatalf("listen mismatch: got %q", cfg.Listen())
	}
	if !cfg.HotReload || !cfg.ConnectionTracking {
		t.Fatalf("features not applied: %+v", cfg)
	}
	if len(cfg.Users) != 1 {
		t.Fatalf("users mismatch: got %d", len(cfg.Users))
	}
	if len(cfg.AllowedUUIDs) != 1 {
		t.Fatalf("allowed uuid derivation mismatch: got %d", len(cfg.AllowedUUIDs))
	}
}

func TestLoadServerJSONRejectsNegativeUserLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	data := `{
  "server": {"listen": ":4433"},
  "security": {"cert_file": "./cert.pem", "key_file": "./key.pem"},
  "users": [
    {
      "uuid": "11111111-1111-1111-1111-111111111111",
      "enabled": true,
      "max_connections": -1
    }
  ]
}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerJSON(path); err == nil {
		t.Fatal("expected error for negative max_connections")
	}
}

func TestLoadServerJSONRejectsDuplicateUserUUID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	data := `{
  "server": {"listen": ":4433"},
  "security": {"cert_file": "./cert.pem", "key_file": "./key.pem"},
  "users": [
    {"uuid": "11111111-1111-1111-1111-111111111111", "enabled": true},
    {"uuid": "11111111-1111-1111-1111-111111111111", "enabled": true}
  ]
}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerJSON(path); err == nil {
		t.Fatal("expected error for duplicate user uuid")
	}
}

func TestLoadServerJSONRejectsNegativeBandwidthLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	data := `{
  "server": {"listen": ":4433"},
  "security": {"cert_file": "./cert.pem", "key_file": "./key.pem"},
  "users": [
    {"uuid": "11111111-1111-1111-1111-111111111111", "enabled": true, "bandwidth_limit": -5}
  ]
}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerJSON(path); err == nil {
		t.Fatal("expected error for negative bandwidth_limit")
	}
}

func TestLoadServerJSONRejectsInvalidExpireAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	data := `{
  "server": {"listen": ":4433"},
  "security": {"cert_file": "./cert.pem", "key_file": "./key.pem"},
  "users": [
    {"uuid": "11111111-1111-1111-1111-111111111111", "enabled": true, "expire_at": "not-time"}
  ]
}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerJSON(path); err == nil {
		t.Fatal("expected error for invalid expire_at")
	}
}
