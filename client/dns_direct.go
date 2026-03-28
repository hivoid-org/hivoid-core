package client

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// DirectDNSResolvers returns UDP addresses (host:port) for resolving queries that
// bypass the tunnel. If explicit is non-empty, those are used (with :53 default).
// Otherwise: nameservers from /etc/resolv.conf on Unix, then 1.1.1.1:53.
func DirectDNSResolvers(explicit []string) []string {
	if len(explicit) > 0 {
		return normalizeDNSAddrs(explicit)
	}
	var out []string
	if runtime.GOOS != "windows" {
		out = append(out, parseResolvConfNameservers()...)
	}
	out = append(out, "1.1.1.1:53")
	return dedupeDNSAddrs(out)
}

func normalizeDNSAddrs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			out = append(out, net.JoinHostPort(s, "53"))
			continue
		}
		if port == "" {
			out = append(out, net.JoinHostPort(host, "53"))
		} else {
			out = append(out, net.JoinHostPort(host, port))
		}
	}
	return dedupeDNSAddrs(out)
}

func dedupeDNSAddrs(in []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(in))
	for _, a := range in {
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

func parseResolvConfNameservers() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var addrs []string
	s := bufio.NewScanner(strings.NewReader(string(b)))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip := strings.TrimSpace(fields[1])
		if ip == "" {
			continue
		}
		ip = strings.TrimPrefix(strings.TrimSuffix(ip, "]"), "[")
		addrs = append(addrs, net.JoinHostPort(ip, "53"))
	}
	return addrs
}

// exchangeDNSUDP sends a raw DNS message via UDP to server and returns the reply.
func exchangeDNSUDP(ctx context.Context, query []byte, server string) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(dnsTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, dnsMaxMsgLen)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 12 {
		return nil, fmt.Errorf("dns udp: short response")
	}
	// Match query id (transaction id).
	if len(query) >= 2 && (buf[0] != query[0] || buf[1] != query[1]) {
		return nil, fmt.Errorf("dns udp: id mismatch")
	}
	return buf[:n], nil
}
