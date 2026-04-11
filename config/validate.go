package config

import (
	"fmt"
	"strings"
)

// validModes is the set of accepted mode strings.
var validModes = map[string]bool{
	"performance":      true,
	"high_performance": true,
	"stealth":          true,
	"balanced":         true,
	"adaptive":         true,
}

// validObfs is the set of accepted obfuscation names.
var validObfs = map[string]bool{
	"none":         true,
	"random":       true,
	"http":         true,
	"tls":          true,
	"ghost":        true,
	"masque":       true,
	"webtransport": true,
}

// Validate returns a descriptive error for any invalid or missing field.
// It is called automatically by ParseURI and LoadJSON.
func (c *Config) Validate() error {
	var errs []string

	// UUID
	if c.UUID == "" {
		errs = append(errs, "uuid: required")
	} else if err := validateUUID(c.UUID); err != nil {
		errs = append(errs, "uuid: "+err.Error())
	}

	// Server
	if c.Server == "" {
		errs = append(errs, "server: required")
	}

	// Port
	if c.Port < 1 || c.Port > 65535 {
		errs = append(errs, fmt.Sprintf("port: must be 1–65535, got %d", c.Port))
	}

	// Mode
	if c.Mode != "" && !validModes[strings.ToLower(c.Mode)] {
		errs = append(errs, fmt.Sprintf("mode: unknown value %q (allowed: performance, stealth, balanced, adaptive)", c.Mode))
	}

	// Obfs
	if c.Obfs != "" && !validObfs[strings.ToLower(c.Obfs)] {
		errs = append(errs, fmt.Sprintf("obfs: unknown value %q (allowed: none, random, http, tls, ghost, masque, webtransport)", c.Obfs))
	}

	// SocksPort
	if c.SocksPort < 0 || c.SocksPort > 65535 {
		errs = append(errs, fmt.Sprintf("socks_port: must be 0–65535, got %d", c.SocksPort))
	}

	// DNSPort
	if c.DNSPort < 0 || c.DNSPort > 65535 {
		errs = append(errs, fmt.Sprintf("dns_port: must be 0–65535, got %d", c.DNSPort))
	}

	// CertPin — if present must be "sha256:<64-hex>" or legacy "<64-hex>"
	if c.CertPin != "" {
		raw := strings.TrimSpace(c.CertPin)
		hexPart := raw
		if strings.HasPrefix(strings.ToLower(raw), "sha256:") {
			hexPart = raw[len("sha256:"):]
		}
		if len(hexPart) != 64 {
			errs = append(errs, fmt.Sprintf("cert_pin: must be sha256:<64 hex> (or 64 hex legacy), got length %d", len(hexPart)))
		} else {
			for _, ch := range hexPart {
				if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
					errs = append(errs, "cert_pin: invalid hex character")
					break
				}
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  • %s", strings.Join(errs, "\n  • "))
	}
	return nil
}
