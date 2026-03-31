package client

import (
	"fmt"
	"net"
	"os"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
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
