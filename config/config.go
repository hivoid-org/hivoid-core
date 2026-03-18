// Package config implements the HiVoid URI and JSON configuration system.
//
// Config strings follow the same compact URI convention as vless/vmess/trojan:
//
//	hivoid://<uuid>@<host>:<port>[?key=value&...]#<name>
//
// Example:
//
//	hivoid://550e8400-e29b-41d4-a716-446655440000@vpn.example.com:443?mode=adaptive&socks-port=1080#Home
//
// Use ParseURI to decode a URI string, Config.URI() to encode, and
// LoadJSON / Config.SaveJSON for JSON file I/O.
package config

// Version is the HiVoid protocol version embedded in the URI scheme.
const Version = 1

// Config holds every configurable parameter for a HiVoid client connection.
// All fields are exported so they marshal cleanly with encoding/json.
type Config struct {
	// UUID is the 36-char RFC 4122 UUID v4 that identifies this client.
	// It is sent in the HiVoid ClientHello and validated server-side.
	// Required.
	UUID string `json:"uuid"`

	// Server is the hostname or IP address of the HiVoid server. Required.
	Server string `json:"server"`

	// Port is the UDP port (QUIC) of the HiVoid server. Required. 1–65535.
	Port int `json:"port"`

	// Mode controls the intelligence engine's operating mode.
	// Values: "performance", "stealth", "balanced", "adaptive" (default).
	Mode string `json:"mode"`

	// Obfs controls traffic obfuscation.
	// Values: "none" (default), "random".
	Obfs string `json:"obfs"`

	// SocksPort is the local TCP port for the SOCKS5/HTTP proxy listener.
	// 0 disables the proxy. Default: 1080.
	SocksPort int `json:"socks_port"`

	// DNSPort is the local UDP port for the DNS-over-tunnel proxy.
	// 0 disables DNS proxying (default).
	DNSPort int `json:"dns_port"`

	// DNSUpstream is the remote DNS server reached through the tunnel.
	// Default: "8.8.8.8:53".
	DNSUpstream string `json:"dns_upstream"`

	// Insecure skips TLS certificate verification. Only for testing.
	// Default: false.
	Insecure bool `json:"insecure"`

	// CertPin is the hex-encoded SHA-256 fingerprint of the expected server
	// TLS certificate. Empty string disables pinning.
	CertPin string `json:"cert_pin"`

	// Name is a human-readable label for this profile (URI fragment #...).
	// Default: "hivoid".
	Name string `json:"name"`
}

// Default values applied when fields are absent in URI / JSON.
const (
	DefaultMode        = "adaptive"
	DefaultObfs        = "none"
	DefaultSocksPort   = 1080
	DefaultDNSPort     = 0
	DefaultDNSUpstream = "8.8.8.8:53"
	DefaultName        = "hivoid"
	Scheme             = "hivoid"
)

// withDefaults fills in zero-value fields with their defaults.
// Called automatically by ParseURI and LoadJSON.
func (c *Config) withDefaults() {
	if c.Mode == "" {
		c.Mode = DefaultMode
	}
	if c.Obfs == "" {
		c.Obfs = DefaultObfs
	}
	if c.SocksPort == 0 {
		c.SocksPort = DefaultSocksPort
	}
	if c.DNSUpstream == "" {
		c.DNSUpstream = DefaultDNSUpstream
	}
	if c.Name == "" {
		c.Name = DefaultName
	}
}

// ServerAddr returns "host:port" suitable for dialing.
func (c *Config) ServerAddr() string {
	return formatHostPort(c.Server, c.Port)
}
