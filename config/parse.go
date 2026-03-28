package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseURI decodes a hivoid:// URI into a Config.
//
//	hivoid://<uuid>@<host>:<port>[?key=value&...]#<name>
//
// All query parameters are optional; defaults are applied for missing fields.
// Returns an error if the scheme is wrong, the UUID is malformed, or required
// fields (host, port) are absent.
func ParseURI(raw string) (*Config, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse uri: %w", err)
	}
	if u.Scheme != Scheme {
		return nil, fmt.Errorf("invalid scheme %q: expected %q", u.Scheme, Scheme)
	}
	if u.User == nil {
		return nil, fmt.Errorf("missing uuid in uri (expected hivoid://<uuid>@host:port)")
	}

	uuid := u.User.Username()
	if err := validateUUID(uuid); err != nil {
		return nil, fmt.Errorf("invalid uuid: %w", err)
	}

	host, portStr, err := splitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host:port %q: %w", u.Host, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}

	q := u.Query()

	cfg := &Config{
		UUID:        uuid,
		Server:      host,
		Port:        port,
		Mode:        q.Get("mode"),
		Obfs:        q.Get("obfs"),
		DNSUpstream: q.Get("dns-up"),
		CertPin:     q.Get("cert-pin"),
		Insecure:    q.Get("insecure") == "true",
		GeoIPPath:   q.Get("geoip-path"),
		GeoSitePath: q.Get("geosite-path"),
		Name:        u.Fragment,
	}

	if bd := q.Get("bypass-domains"); bd != "" {
		cfg.BypassDomains = strings.Split(bd, ",")
	}
	if bi := q.Get("bypass-ips"); bi != "" {
		cfg.BypassIPs = strings.Split(bi, ",")
	}
	if dr := q.Get("direct-route"); dr != "" {
		cfg.DirectRoute = strings.Split(dr, ",")
	}

	if ps := q.Get("pool-size"); ps != "" {
		v, err := strconv.Atoi(ps)
		if err == nil && v > 0 {
			cfg.PoolSize = v
		}
	}

	if sp := q.Get("socks-port"); sp != "" {
		v, err := strconv.Atoi(sp)
		if err == nil {
			cfg.SocksPort = v
		}
	}
	if dp := q.Get("dns-port"); dp != "" {
		v, err := strconv.Atoi(dp)
		if err == nil {
			cfg.DNSPort = v
		}
	}

	cfg.withDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config from uri: %w", err)
	}
	return cfg, nil
}

// UUIDBytes parses the UUID string into a 16-byte array.
// Returns an error if the UUID is not a valid RFC 4122 format.
func (c *Config) UUIDBytes() ([16]byte, error) {
	return parseUUIDBytes(c.UUID)
}

// parseUUIDBytes converts "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" → [16]byte.
func parseUUIDBytes(s string) ([16]byte, error) {
	var out [16]byte
	// Strip hyphens
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return out, fmt.Errorf("expected 32 hex chars after stripping hyphens, got %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return out, fmt.Errorf("uuid hex decode: %w", err)
	}
	copy(out[:], b)
	return out, nil
}

// validateUUID checks that s is a well-formed RFC 4122 UUID.
func validateUUID(s string) error {
	// "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" = 36 chars
	if len(s) != 36 {
		return fmt.Errorf("must be 36 characters, got %d", len(s))
	}
	dashes := []int{8, 13, 18, 23}
	for _, d := range dashes {
		if s[d] != '-' {
			return fmt.Errorf("expected '-' at position %d", d)
		}
	}
	clean := strings.ReplaceAll(s, "-", "")
	for _, c := range clean {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("invalid hex character %q", c)
		}
	}
	return nil
}

// splitHostPort splits "host:port" or "[ipv6]:port" without stdlib net.
func splitHostPort(s string) (host, port string, err error) {
	if len(s) == 0 {
		return "", "", fmt.Errorf("empty host:port")
	}
	// IPv6 literal: [::1]:443
	if s[0] == '[' {
		end := strings.LastIndex(s, "]")
		if end < 0 {
			return "", "", fmt.Errorf("missing ']'")
		}
		host = s[1:end]
		rest := s[end+1:]
		if len(rest) == 0 || rest[0] != ':' {
			return "", "", fmt.Errorf("missing ':' after ']'")
		}
		port = rest[1:]
		return host, port, nil
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("missing ':' separator")
	}
	return s[:idx], s[idx+1:], nil
}

// formatHostPort joins host and port into "host:port", bracketing IPv6.
func formatHostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
