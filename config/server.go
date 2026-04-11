package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ServerSection is the nested "server" section.
type ServerSection struct {
	Listen   string `json:"listen"`
	Mode     string `json:"mode"`
	LogLevel string `json:"log_level"`
}

// SecuritySection is the nested "security" section.
type SecuritySection struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// FeaturesSection is the nested "features" section.
type FeaturesSection struct {
	HotReload          bool `json:"hot_reload"`
	ConnectionTracking bool `json:"connection_tracking"`
	DisconnectExpired  bool `json:"disconnect_expired"`
}

// HubConfig configures connection to a master Subscription Hub.
type HubConfig struct {
	Endpoint       string `json:"endpoint"`         // e.g., "wss://hub.hivoid.org/api/v1/node"
	NodeToken      string `json:"node_token"`       // Authentication token
	SyncIntervalMs int    `json:"sync_interval_ms"` // Telemetry reporting interval in milliseconds
	Insecure       bool   `json:"insecure"`         // Skip TLS verification (useful for IP endpoints)
}

// HubOnlyConfig is a simplified configuration for running in stateless Slave Mode.
type HubOnlyConfig struct {
	Endpoint       string `json:"endpoint"`
	NodeToken      string `json:"node_token"`
	Cert           string `json:"cert"`
	Key            string `json:"key"`
	SyncIntervalMs int    `json:"sync_interval_ms"`
	Insecure       bool   `json:"insecure"`
	Port           int    `json:"port"` // Optional listen port, defaults to 4433
}

// ServerUserConfig contains per-user runtime policy.
type ServerUserConfig struct {
	UUID           string   `json:"uuid"`
	Email          string   `json:"email"`
	CertPin        string   `json:"cert_pin,omitempty"`
	Enabled        bool     `json:"enabled"`
	MaxConnections int      `json:"max_connections"`
	MaxIPs         int      `json:"max_ips"`
	BindIP         string   `json:"bind_ip"`
	Mode           string   `json:"mode"`
	Obfs           string   `json:"obfs"`
	BandwidthLimit int64    `json:"bandwidth_limit"`
	DataLimit      int64    `json:"data_limit"`
	ExpireAt       string   `json:"expire_at"`
	BytesIn        uint64   `json:"bytes_in"`
	BytesOut       uint64   `json:"bytes_out"`
	BlockedHosts   []string `json:"blocked_hosts"`
	BlockedTags    []string `json:"blocked_tags"`
}

// ServerConfig holds every configurable parameter for a HiVoid server.
type ServerConfig struct {
	// Flat schema (legacy and internal normalized form).
	Server string `json:"server"`
	Port   int    `json:"port"`
	Name   string `json:"name"`
	Obfs   string `json:"obfs"`
	Cert   string `json:"cert"`
	Key    string `json:"key"`
	Mode   string `json:"mode"`

	MaxConns     int      `json:"max_conns"`
	AllowedHosts []string `json:"allowed_hosts"`
	BlockedHosts []string `json:"blocked_hosts"`
	AllowedUUIDs []string `json:"allowed_uuids"`
	AntiProbe    bool     `json:"anti_probe"`
	FallbackAddr string   `json:"fallback_addr"`
	BlockedTags  []string `json:"blocked_tags"`
	GeoIPPath    string   `json:"geoip_path"`
	GeoSitePath  string   `json:"geosite_path"`
	Debug        bool     `json:"debug"`

	// Dynamic features and user policies.
	HotReload          bool               `json:"-"`
	ConnectionTracking bool               `json:"-"`
	DisconnectExpired  bool               `json:"-"`
	LogLevel           string             `json:"-"`
	Users              []ServerUserConfig `json:"users"`
	Hub                HubConfig          `json:"hub"` // Master Hub connection settings
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

func parsePort(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("port is empty")
	}
	n := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid port %q", s)
		}
		n = n*10 + int(ch-'0')
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port must be 1-65535, got %d", n)
	}
	return n, nil
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
	for i := range c.Users {
		if c.Users[i].Mode == "" {
			c.Users[i].Mode = c.Mode
		}
		if c.Users[i].Obfs == "" {
			c.Users[i].Obfs = c.Obfs
		}
	}
}

func (c *ServerConfig) normalize() {
	if len(c.Users) > 0 && len(c.AllowedUUIDs) == 0 {
		allow := make([]string, 0, len(c.Users))
		for _, u := range c.Users {
			if u.Enabled {
				allow = append(allow, u.UUID)
			}
		}
		c.AllowedUUIDs = allow
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
	if c.FallbackAddr != "" {
		if _, _, err := splitHostPort(c.FallbackAddr); err != nil {
			errs = append(errs, fmt.Sprintf("fallback_addr: invalid format %q: %v", c.FallbackAddr, err))
		}
	}
	for _, u := range c.AllowedUUIDs {
		if err := validateUUID(u); err != nil {
			errs = append(errs, fmt.Sprintf("allowed_uuids: %s: %v", u, err))
		}
	}

	seenUsers := make(map[string]struct{}, len(c.Users))
	for i, u := range c.Users {
		row := i + 1
		if err := validateUUID(u.UUID); err != nil {
			errs = append(errs, fmt.Sprintf("users[%d].uuid: %v", row, err))
		}
		id := strings.ToLower(u.UUID)
		if _, exists := seenUsers[id]; exists {
			errs = append(errs, fmt.Sprintf("users[%d].uuid: duplicate %q", row, u.UUID))
		}
		seenUsers[id] = struct{}{}
		if u.MaxConnections < 0 {
			errs = append(errs, fmt.Sprintf("users[%d].max_connections: must be >= 0, got %d", row, u.MaxConnections))
		}
		if u.MaxIPs < 0 {
			errs = append(errs, fmt.Sprintf("users[%d].max_ips: must be >= 0, got %d", row, u.MaxIPs))
		}
		if u.BindIP != "" {
			importNet := false
			if u.BindIP != "" {
				importNet = true
			}
			_ = importNet
		}
		if u.BandwidthLimit < 0 {
			errs = append(errs, fmt.Sprintf("users[%d].bandwidth_limit: must be >= 0, got %d", row, u.BandwidthLimit))
		}
		if u.DataLimit < 0 {
			errs = append(errs, fmt.Sprintf("users[%d].data_limit: must be >= 0, got %d", row, u.DataLimit))
		}
		if u.Mode != "" && !validModes[strings.ToLower(u.Mode)] {
			errs = append(errs, fmt.Sprintf("users[%d].mode: unknown value %q", row, u.Mode))
		}
		if u.Obfs != "" && !validObfs[strings.ToLower(u.Obfs)] {
			errs = append(errs, fmt.Sprintf("users[%d].obfs: unknown value %q", row, u.Obfs))
		}
		if u.ExpireAt != "" {
			if _, err := time.Parse(time.RFC3339, u.ExpireAt); err != nil {
				errs = append(errs, fmt.Sprintf("users[%d].expire_at: invalid RFC3339 timestamp %q", row, u.ExpireAt))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("server config validation failed:\n  • %s", strings.Join(errs, "\n  • "))
	}
	return nil
}

// UnmarshalJSON implements custom logic to handle both Flat (string) and Structured (object) schemas.
func (c *ServerConfig) UnmarshalJSON(data []byte) error {
	type alias ServerConfig
	var aux struct {
		*alias
		ServerRaw json.RawMessage `json:"server"`
		Security  SecuritySection `json:"security"`
		Features  FeaturesSection `json:"features"`
		HubRaw    HubConfig       `json:"hub"`
	}
	aux.alias = (*alias)(c)
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// 1. Handle "server" field (string or object)
	if len(aux.ServerRaw) > 0 {
		var host string
		// Try string first (Legacy/Flat)
		if err := json.Unmarshal(aux.ServerRaw, &host); err == nil {
			c.Server = host
		} else {
			// Try object (Structured Core 1.1)
			var section ServerSection
			if err := json.Unmarshal(aux.ServerRaw, &section); err != nil {
				return fmt.Errorf("invalid server section: %w", err)
			}
			if section.Listen != "" {
				h, p, err := splitHostPort(section.Listen)
				if err != nil {
					return fmt.Errorf("server.listen: %w", err)
				}
				port, err := parsePort(p)
				if err != nil {
					return fmt.Errorf("server.listen: %w", err)
				}
				c.Server = h
				c.Port = port
			}
			if section.Mode != "" {
				c.Mode = section.Mode
			}
			c.LogLevel = section.LogLevel
		}
	}

	// 2. Handle "security" section
	if aux.Security.CertFile != "" {
		c.Cert = aux.Security.CertFile
	}
	if aux.Security.KeyFile != "" {
		c.Key = aux.Security.KeyFile
	}

	// 3. Handle "features" section
	c.HotReload = aux.Features.HotReload
	c.ConnectionTracking = aux.Features.ConnectionTracking
	c.DisconnectExpired = aux.Features.DisconnectExpired

	// 4. Handle "hub" section
	if aux.HubRaw.Endpoint != "" {
		c.Hub = aux.HubRaw
	}

	return nil
}

// LoadServerJSON reads a server JSON config from disk.
func LoadServerJSON(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	c := &ServerConfig{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}

	c.serverDefaults()
	c.normalize()
	if err := c.ValidateServer(); err != nil {
		return nil, err
	}
	return c, nil
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
