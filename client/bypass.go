package client

import (
	"net"
	"strings"

	"go.uber.org/zap"
)

// HostMatchesBypass reports whether host should bypass the tunnel (direct),
// using the same domain suffix and CIDR rules as the SOCKS/HTTP proxy.
func HostMatchesBypass(host string, bypassDomains []string, bypassIPs []*net.IPNet) bool {
	if len(bypassDomains) == 0 && len(bypassIPs) == 0 {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return false
	}
	for _, domain := range bypassDomains {
		d := strings.ToLower(strings.TrimSpace(domain))
		if d == "" {
			continue
		}
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, ipnet := range bypassIPs {
			if ipnet != nil && ipnet.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// ParseBypassIPStrings parses bypass IP strings (CIDR or single IP) into *net.IPNet.
func ParseBypassIPStrings(ipStrs []string, log *zap.Logger) []*net.IPNet {
	var out []*net.IPNet
	for _, ipStr := range ipStrs {
		_, ipnet, err := net.ParseCIDR(ipStr)
		if err == nil {
			out = append(out, ipnet)
			continue
		}
		if ip := net.ParseIP(ipStr); ip != nil {
			if ip.To4() != nil {
				_, ipnet, err = net.ParseCIDR(ipStr + "/32")
			} else {
				_, ipnet, err = net.ParseCIDR(ipStr + "/128")
			}
			if err == nil && ipnet != nil {
				out = append(out, ipnet)
			}
			continue
		}
		if log != nil {
			log.Warn("invalid bypass IP or CIDR", zap.String("value", ipStr))
		}
	}
	return out
}
