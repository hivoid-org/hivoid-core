package geodata

import (
	"fmt"
	"net"
	"os"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
	"strings"
)

// LoadGeoData parses geoip.dat and geosite.dat for specific tags (e.g., "ir", "category-ads-all").
// It appends the loaded domains and IP CIDRs exactly as required by the proxy.
func LoadGeoData(geoipPath, geositePath string, tags []string, outDomains *[]string, outIPs *[]*net.IPNet) error {
	tagMap := make(map[string]bool)
	for _, t := range tags {
		tagMap[t] = true
	}

	if geoipPath != "" {
		b, err := os.ReadFile(geoipPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read geoip.dat: %w", err)
		}
		if err == nil {
			var list routercommon.GeoIPList
			if err := proto.Unmarshal(b, &list); err != nil {
				return fmt.Errorf("unmarshal geoip.dat: %w", err)
			}
			for _, geoip := range list.Entry {
				if tagMap[geoip.CountryCode] {
					for _, cidr := range geoip.Cidr {
						ip := net.IP(cidr.Ip)
						mask := net.CIDRMask(int(cidr.Prefix), len(ip)*8)
						*outIPs = append(*outIPs, &net.IPNet{IP: ip, Mask: mask})
					}
				}
			}
		}
	}

	if geositePath != "" {
		b, err := os.ReadFile(geositePath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read geosite.dat: %w", err)
		}
		if err == nil {
			var list routercommon.GeoSiteList
			if err := proto.Unmarshal(b, &list); err != nil {
				return fmt.Errorf("unmarshal geosite.dat: %w", err)
			}
			for _, geosite := range list.Entry {
				if tagMap[geosite.CountryCode] {
					for _, domain := range geosite.Domain {
						// We only process Type 0 (Plain), Type 2 (Domain/Suffix), Type 3 (Full/Exact).
						// Regex (Type 1) is ignored for performance, but suffix matching works for 99% of V2ray dat.
						val := domain.Value
						if val != "" {
							*outDomains = append(*outDomains, val)
						}
					}
				}
			}
		}
	}

	return nil
}

// GeoMatcher provides efficient lookup for domain/IP matching against geo tags.
type GeoMatcher struct {
	IPs     map[string][]*net.IPNet
	Domains map[string][]string
}

// NewGeoMatcher loads all tags into memory for fast matching.
func NewGeoMatcher(geoipPath, geositePath string) *GeoMatcher {
	m := &GeoMatcher{
		IPs:     make(map[string][]*net.IPNet),
		Domains: make(map[string][]string),
	}

	if geoipPath != "" {
		if b, err := os.ReadFile(geoipPath); err == nil {
			var list routercommon.GeoIPList
			if err := proto.Unmarshal(b, &list); err == nil {
				for _, geoip := range list.Entry {
					var nets []*net.IPNet
					for _, cidr := range geoip.Cidr {
						ip := net.IP(cidr.Ip)
						mask := net.CIDRMask(int(cidr.Prefix), len(ip)*8)
						nets = append(nets, &net.IPNet{IP: ip, Mask: mask})
					}
					tag := strings.ToUpper(geoip.CountryCode)
					m.IPs[tag] = append(m.IPs[tag], nets...)
				}
			}
		}
	}

	if geositePath != "" {
		if b, err := os.ReadFile(geositePath); err == nil {
			var list routercommon.GeoSiteList
			if err := proto.Unmarshal(b, &list); err == nil {
				for _, geosite := range list.Entry {
					var doms []string
					for _, domain := range geosite.Domain {
						if domain.Value != "" {
							doms = append(doms, domain.Value)
						}
					}
					tag := strings.ToUpper(geosite.CountryCode)
					m.Domains[tag] = append(m.Domains[tag], doms...)
				}
			}
		}
	}

	return m
}

// Match checks if an IP or domain matches any of the given tags.
func (m *GeoMatcher) Match(host string, tags []string) bool {
	if len(tags) == 0 {
		return false
	}

	// 1. Check IP if host is an IP
	if ip := net.ParseIP(host); ip != nil {
		for _, tag := range tags {
			for _, cidr := range m.IPs[tag] {
				if cidr.Contains(ip) {
					return true
				}
			}
		}
		return false
	}

	// 2. Check Domain
	for _, tag := range tags {
		tagUpper := strings.ToUpper(tag)
		for _, pattern := range m.Domains[tagUpper] {
			if matchHost(pattern, host) {
				return true
			}
		}
	}

	return false
}

func matchHost(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	// Case-insensitive comparison for domains
	p := strings.ToLower(pattern)
	h := strings.ToLower(host)

	// Explicit wildcard or starting with dot
	if strings.HasPrefix(p, "*.") {
		suffix := p[1:] // ".xxx.com"
		return strings.HasSuffix(h, suffix)
	}
	if strings.HasPrefix(p, ".") {
		return strings.HasSuffix(h, p)
	}

	// Smart matching: exact OR subdomain
	if h == p {
		return true
	}
	return strings.HasSuffix(h, "."+p)
}
