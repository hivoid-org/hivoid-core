package geodata

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// LoadGeoData parses geoip.dat and geosite.dat for specific tags (e.g., "ir", "category-ads-all").
// It appends the loaded domains and IP CIDRs exactly as required by the proxy.
func LoadGeoData(geoipPath, geositePath string, tags []string, outDomains *[]string, outIPs *[]*net.IPNet) error {
	tagMap := make(map[string]bool)
	for _, t := range tags {
		tagMap[strings.ToUpper(t)] = true
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
				if tagMap[strings.ToUpper(geoip.CountryCode)] {
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
				if tagMap[strings.ToUpper(geosite.CountryCode)] {
					for _, domain := range geosite.Domain {
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
	IPs     map[string][]*net.IPNet // key = UPPERCASE tag
	Domains map[string][]string    // key = UPPERCASE tag
	logger  *zap.Logger
}

// NewGeoMatcher loads ALL tags from geoip.dat and geosite.dat into memory.
// Returns a populated matcher and logs diagnostic information.
func NewGeoMatcher(geoipPath, geositePath string, logger *zap.Logger) *GeoMatcher {
	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	m := &GeoMatcher{
		IPs:     make(map[string][]*net.IPNet),
		Domains: make(map[string][]string),
		logger:  logger,
	}

	totalIPs := 0
	if geoipPath != "" {
		b, err := os.ReadFile(geoipPath)
		if err != nil {
			logger.Warn("geodata: failed to read geoip file", zap.String("path", geoipPath), zap.Error(err))
		} else {
			var list routercommon.GeoIPList
			if err := proto.Unmarshal(b, &list); err != nil {
				logger.Warn("geodata: failed to unmarshal geoip file", zap.String("path", geoipPath), zap.Error(err))
			} else {
				for _, geoip := range list.Entry {
					tag := strings.ToUpper(geoip.CountryCode)
					for _, cidr := range geoip.Cidr {
						ip := net.IP(cidr.Ip)
						mask := net.CIDRMask(int(cidr.Prefix), len(ip)*8)
						m.IPs[tag] = append(m.IPs[tag], &net.IPNet{IP: ip, Mask: mask})
						totalIPs++
					}
				}
				logger.Info("geodata: geoip loaded",
					zap.String("path", geoipPath),
					zap.Int("tags", len(m.IPs)),
					zap.Int("total_cidrs", totalIPs),
				)
			}
		}
	}

	totalDomains := 0
	if geositePath != "" {
		b, err := os.ReadFile(geositePath)
		if err != nil {
			logger.Warn("geodata: failed to read geosite file", zap.String("path", geositePath), zap.Error(err))
		} else {
			var list routercommon.GeoSiteList
			if err := proto.Unmarshal(b, &list); err != nil {
				logger.Warn("geodata: failed to unmarshal geosite file", zap.String("path", geositePath), zap.Error(err))
			} else {
				for _, geosite := range list.Entry {
					tag := strings.ToUpper(geosite.CountryCode)
					for _, domain := range geosite.Domain {
						if domain.Value != "" {
							m.Domains[tag] = append(m.Domains[tag], domain.Value)
							totalDomains++
						}
					}
				}
				logger.Info("geodata: geosite loaded",
					zap.String("path", geositePath),
					zap.Int("tags", len(m.Domains)),
					zap.Int("total_domains", totalDomains),
				)
			}
		}
	}

	return m
}

// TagDomainCount returns how many domain entries exist for a given tag.
// Useful for diagnostics.
func (m *GeoMatcher) TagDomainCount(tag string) int {
	return len(m.Domains[strings.ToUpper(tag)])
}

// TagIPCount returns how many IP CIDR entries exist for a given tag.
func (m *GeoMatcher) TagIPCount(tag string) int {
	return len(m.IPs[strings.ToUpper(tag)])
}

// Match checks if an IP or domain matches any of the given tags.
func (m *GeoMatcher) Match(host string, tags []string) bool {
	if m == nil || len(tags) == 0 {
		return false
	}

	// Normalize host
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")

	// 1. Check IP if host is an IP
	if ip := net.ParseIP(host); ip != nil {
		for _, tag := range tags {
			tagUpper := strings.ToUpper(tag)
			for _, cidr := range m.IPs[tagUpper] {
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
			if matchDomain(pattern, host) {
				return true
			}
		}
	}

	return false
}

// matchDomain checks if host matches a GeoSite domain entry.
// Supports:
//   - Exact match: "cpmstar.com" == "cpmstar.com"
//   - Subdomain match: "www.cpmstar.com" matches "cpmstar.com"
//   - Wildcard: "*.example.com" matches "sub.example.com"
//   - Dot-prefix: ".example.com" matches "sub.example.com"
func matchDomain(pattern, host string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	h := host // already lowercased by caller

	if p == "" || h == "" {
		return false
	}
	if p == "*" {
		return true
	}

	// Wildcard prefix: *.example.com
	if strings.HasPrefix(p, "*.") {
		suffix := p[1:] // ".example.com"
		return strings.HasSuffix(h, suffix)
	}
	// Dot prefix: .example.com
	if p[0] == '.' {
		return strings.HasSuffix(h, p)
	}

	// Exact match
	if h == p {
		return true
	}
	// Subdomain match: host "www.cpmstar.com" matches pattern "cpmstar.com"
	return strings.HasSuffix(h, "."+p)
}
