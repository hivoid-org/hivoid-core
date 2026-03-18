package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ServerConfig holds every configurable parameter for a HiVoid server.
type ServerConfig struct {
	// Server is the hostname or IP to bind (used with Port to form listen address).
	Server string `json:"server"`

	// Port is the UDP port (QUIC) to listen on.
	Port int `json:"port"`

	// Obfs controls traffic obfuscation (none, random).
	Obfs string `json:"obfs"`

	// Cert is the path to the TLS certificate (PEM).
	Cert string `json:"cert"`

	// Key is the path to the TLS private key (PEM).
	Key string `json:"key"`

	// Mode controls the intelligence engine (performance|stealth|balanced|adaptive).
	Mode string `json:"mode"`

	// MaxConns is the maximum number of concurrent proxy connections (0 = unlimited).
	MaxConns int `json:"max_conns"`

	// AllowedHosts is a list of allowed destination host patterns (empty = all).
	AllowedHosts []string `json:"allowed_hosts"`

	// BlockedHosts is a list of blocked destination host patterns.
	BlockedHosts []string `json:"blocked_hosts"`

	// AllowedUUIDs is the list of client UUIDs allowed to connect (empty = all).
	AllowedUUIDs []string `json:"allowed_uuids"`

	// Debug enables debug-level logging.
	Debug bool `json:"debug"`
}

// Listen returns "host:port" for the QUIC listener.
func (c *ServerConfig) Listen() string {
	host := c.Server
	port := c.Port
	if port == 0 {
		port = 4433
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// serverDefaults fills in zero-value fields with their defaults.
func (c *ServerConfig) serverDefaults() {
	if c.Port == 0 {
		c.Port = 4433
	}
	if c.Cert == "" {
		c.Cert = "cert.pem"
	}
	if c.Key == "" {
		c.Key = "key.pem"
	}
	if c.Mode == "" {
		c.Mode = DefaultMode
	}
	if c.Obfs == "" {
		c.Obfs = DefaultObfs
	}
}

// ValidateServer returns a descriptive error for any invalid field.
func (c *ServerConfig) ValidateServer() error {
	var errs []string

	if c.Port < 1 || c.Port > 65535 {
		errs = append(errs, fmt.Sprintf("port: must be 1–65535, got %d", c.Port))
	}
	if c.Cert == "" {
		errs = append(errs, "cert: required")
	}
	if c.Key == "" {
		errs = append(errs, "key: required")
	}
	if c.Mode != "" && !validModes[strings.ToLower(c.Mode)] {
		errs = append(errs, fmt.Sprintf("mode: unknown value %q", c.Mode))
	}
	if c.Obfs != "" && !validObfs[strings.ToLower(c.Obfs)] {
		errs = append(errs, fmt.Sprintf("obfs: unknown value %q", c.Obfs))
	}
	if c.MaxConns < 0 {
		errs = append(errs, fmt.Sprintf("max_conns: must be >= 0, got %d", c.MaxConns))
	}
	for _, u := range c.AllowedUUIDs {
		if err := validateUUID(u); err != nil {
			errs = append(errs, fmt.Sprintf("allowed_uuids: %s: %v", u, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("server config validation failed:\n  • %s", strings.Join(errs, "\n  • "))
	}
	return nil
}

// LoadServerJSON reads a server JSON config from disk.
func LoadServerJSON(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c ServerConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.serverDefaults()
	if err := c.ValidateServer(); err != nil {
		return nil, err
	}
	return &c, nil
}

// UUIDBytesList parses all AllowedUUIDs into [16]byte values.
func (c *ServerConfig) UUIDBytesList() [][16]byte {
	var out [][16]byte
	for _, raw := range c.AllowedUUIDs {
		b, err := parseUUIDBytes(raw)
		if err == nil {
			out = append(out, b)
		}
	}
	return out
}
