// Package config implements the HiVoid URI and JSON configuration system.
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

import "strings"

// Version is the HiVoid protocol version embedded in the URI scheme.
const Version = 1

// Config holds every configurable parameter for a HiVoid client connection.
// All fields are exported so they marshal cleanly with encoding/json.
type Config struct {
	// UUID is the 36-char RFC 4122 UUID v4 that identifies this client.
	// It is sent in the HiVoid ClientHello and validated server-side.
	// Required.
	UUID string `json:"uuid"`

	// Servers is a list of host:port strings. If provided, Server and Port are ignored.
	Servers []string `json:"servers,omitempty"`

	// Server is the hostname or IP address of the HiVoid server. Required if Servers is empty.
	Server string `json:"server"`

	// Port is the UDP port (QUIC) of the HiVoid server. Required if Servers is empty. 1–65535.
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

	// CertPin is the expected server certificate fingerprint.
	// Preferred format: "sha256:<64-hex>", legacy "<64-hex>" is also accepted.
	// Empty string disables pinning.
	CertPin string `json:"cert_pin"`

	// Name is a human-readable label for this profile (URI fragment #...).
	// Default: "hivoid".
	Name string `json:"name"`

	// BypassDomains is a list of domain suffixes (e.g. ".ir", "localhost") to route directly.
	BypassDomains []string `json:"bypass_domains,omitempty"`

	// BypassIPs is a list of IPs or CIDRs (e.g. "10.0.0.0/8") to route directly.
	BypassIPs []string `json:"bypass_ips,omitempty"`

	// GeoIPPath is the path to the v2ray geoip.dat file.
	GeoIPPath string `json:"geoip_path,omitempty"`

	// GeoSitePath is the path to the v2ray geosite.dat file.
	GeoSitePath string `json:"geosite_path,omitempty"`

	// DirectRoute specifies which Country/Tags from GeoIP and GeoSite should be bypassed (Direct).
	// Example: ["us", "category-us"]
	DirectRoute []string `json:"direct_route,omitempty"`

	// DirectGeoSite specifies geosite tags routed directly.
	DirectGeoSite []string `json:"direct_geosite,omitempty"`

	// DirectGeoIP specifies geoip tags routed directly.
	DirectGeoIP []string `json:"direct_geoip,omitempty"`

	// DirectDomains specifies explicit domains routed directly.
	DirectDomains []string `json:"direct_domains,omitempty"`

	// DirectIPs specifies explicit IP/CIDR values routed directly.
	DirectIPs []string `json:"direct_ips,omitempty"`

	DirectDNSServers []string `json:"direct_dns_servers,omitempty"`

	// PoolSize determines how many independent QUIC connections are established
	// to the server to bypass per-connection ISP throttling.
	// Default: 4. Max: 16.
	PoolSize int `json:"pool_size,omitempty"`

	// Persistence enables saving of engine metrics (Jitter, RTT, Threat) to disk.
	Persistence bool `json:"persistence,omitempty"`

	// StateFile is the path where engine metrics are stored if Persistence is enabled.
	StateFile string `json:"state_file,omitempty"`
}

// Default values applied when fields are absent in URI / JSON.
const (
	DefaultMode        = "adaptive"
	DefaultObfs        = "none"
	DefaultSocksPort   = 1080
	DefaultDNSPort     = 0
	DefaultDNSUpstream = "8.8.8.8:53"
	DefaultPoolSize    = 4
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
	if c.PoolSize == 0 {
		c.PoolSize = DefaultPoolSize
	}
	if c.Name == "" {
		c.Name = DefaultName
	}
}

// ServerAddrs returns all configured "host:port" addresses.
func (c *Config) ServerAddrs() []string {
	if len(c.Servers) > 0 {
		return c.Servers
	}
	if c.Server != "" && c.Port != 0 {
		return []string{formatHostPort(c.Server, c.Port)}
	}
	return nil
}

// ServerAddr returns the primary "host:port" address (for logging/legacy).
func (c *Config) ServerAddr() string {
	addrs := c.ServerAddrs()
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

// EffectiveBypassDomains returns merged direct-domain rules.
// It combines legacy bypass_domains with direct_domains.
func (c *Config) EffectiveBypassDomains() []string {
	return appendUniqueTrimmed(c.BypassDomains, c.DirectDomains)
}

// EffectiveBypassIPs returns merged direct IP/CIDR rules.
// It combines legacy bypass_ips with direct_ips.
func (c *Config) EffectiveBypassIPs() []string {
	return appendUniqueTrimmed(c.BypassIPs, c.DirectIPs)
}

// EffectiveDirectRouteTags returns merged geodata tags.
// It combines legacy direct_route with direct_geosite and direct_geoip.
func (c *Config) EffectiveDirectRouteTags() []string {
	out := appendUniqueTrimmed(c.DirectRoute, c.DirectGeoSite)
	return appendUniqueTrimmed(out, c.DirectGeoIP)
}

func appendUniqueTrimmed(base []string, extra []string) []string {
	seen := make(map[string]bool, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, s := range base {
		t := strings.TrimSpace(s)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, s := range extra {
		t := strings.TrimSpace(s)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}
