package config

import (
	"fmt"
	"net/url"
	"strconv"
)

// URI encodes the Config as a hivoid:// URI string suitable for sharing,
// QR codes, and import into other HiVoid-compatible clients.
//
// Only non-default values are included as query parameters to keep the URI
// short. The UUID appears as the userinfo component; the name appears as the
// URL fragment.
//
// Example output:
//
//	hivoid://550e8400-e29b-41d4-a716-446655440000@vpn.example.com:443?mode=stealth&socks-port=1080#Home
func (c *Config) URI() string {
	// Build query parameters — omit defaults to stay compact
	q := url.Values{}

	if c.Mode != "" && c.Mode != DefaultMode {
		q.Set("mode", c.Mode)
	}
	if c.Obfs != "" && c.Obfs != DefaultObfs {
		q.Set("obfs", c.Obfs)
	}
	if c.SocksPort != 0 && c.SocksPort != DefaultSocksPort {
		q.Set("socks-port", strconv.Itoa(c.SocksPort))
	}
	if c.DNSPort != 0 {
		q.Set("dns-port", strconv.Itoa(c.DNSPort))
	}
	if c.DNSUpstream != "" && c.DNSUpstream != DefaultDNSUpstream {
		q.Set("dns-up", c.DNSUpstream)
	}
	if c.Insecure {
		q.Set("insecure", "true")
	}
	if c.CertPin != "" {
		q.Set("cert-pin", c.CertPin)
	}

	// If ALL fields are default, still emit socks-port so the URI is useful
	if len(q) == 0 && c.SocksPort > 0 {
		q.Set("socks-port", strconv.Itoa(c.SocksPort))
	}

	name := c.Name
	if name == "" {
		name = DefaultName
	}

	u := &url.URL{
		Scheme:   Scheme,
		User:     url.User(c.UUID),
		Host:     formatHostPort(c.Server, c.Port),
		RawQuery: q.Encode(),
		Fragment: name,
	}

	return u.String()
}

// PrettyJSON returns a human-readable JSON representation of the config.
// Useful for `hivoid export --uri hivoid://...` to print expanded fields.
func (c *Config) PrettyJSON() string {
	return fmt.Sprintf(`{
  "uuid":         %q,
  "server":       %q,
  "port":         %d,
  "mode":         %q,
  "obfs":         %q,
  "socks_port":   %d,
  "dns_port":     %d,
  "dns_upstream": %q,
  "insecure":     %t,
  "cert_pin":     %q,
  "name":         %q
}`,
		c.UUID,
		c.Server,
		c.Port,
		c.Mode,
		c.Obfs,
		c.SocksPort,
		c.DNSPort,
		c.DNSUpstream,
		c.Insecure,
		c.CertPin,
		c.Name,
	)
}
