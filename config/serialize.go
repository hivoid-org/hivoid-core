package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
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
	if c.PoolSize > 0 && c.PoolSize != DefaultPoolSize {
		q.Set("pool-size", strconv.Itoa(c.PoolSize))
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
		q.Set("cert_pin", c.CertPin)
	}
	if len(c.BypassDomains) > 0 {
		q.Set("bypass-domains", strings.Join(c.BypassDomains, ","))
	}
	if len(c.BypassIPs) > 0 {
		q.Set("bypass-ips", strings.Join(c.BypassIPs, ","))
	}
	if c.GeoIPPath != "" {
		q.Set("geoip-path", c.GeoIPPath)
	}
	if c.GeoSitePath != "" {
		q.Set("geosite-path", c.GeoSitePath)
	}
	if len(c.DirectRoute) > 0 {
		q.Set("direct-route", strings.Join(c.DirectRoute, ","))
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
  "dns_upstream":   %q,
  "insecure":       %t,
  "cert_pin":       %q,
  "bypass_domains": %q,
  "bypass_ips":     %q,
  "geoip_path":     %q,
  "geosite_path":   %q,
  "direct_route":   %q,
  "pool_size":      %d,
  "name":           %q
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
		strings.Join(c.BypassDomains, ","),
		strings.Join(c.BypassIPs, ","),
		c.GeoIPPath,
		c.GeoSitePath,
		strings.Join(c.DirectRoute, ","),
		c.PoolSize,
		c.Name,
	)
}
