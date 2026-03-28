// Package client — DNS-over-tunnel proxy.
//
// DNSProxy listens for DNS queries on a local UDP port. Queries whose QNAME
// matches the same bypass rules as the SOCKS proxy (manual lists + geosite/geoip)
// are resolved via the machine's normal resolvers (Unix: /etc/resolv.conf) and
// 1.1.1.1, so domestic/direct hosts avoid round-trips through the tunnel.
// All other queries go through the HiVoid tunnel to the configured upstream
// (default 8.8.8.8), limiting DNS leaks for non-bypass traffic.
//
// DNS-over-tunnel protocol:
//  1. Client proxy receives a raw DNS query over UDP
//  2. A tunnel connection is opened to the DNS server (default: 8.8.8.8:53)
//  3. The raw DNS message is sent over the tunnel wrapped in a length-prefixed
//     TCP framing (RFC 1035 §4.2.2), since the tunnel uses a TCP-like stream
//  4. The response is forwarded back to the original UDP client
package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// dnsMaxMsgLen is the maximum DNS-over-TCP message length (RFC 1035).
	dnsMaxMsgLen = 65535
	// dnsTimeout is the per-query timeout.
	dnsTimeout = 5 * time.Second
	// defaultUpstreamDNS is the upstream DNS resolver the server uses.
	defaultUpstreamDNS = "8.8.8.8:53"
)

// DNSProxyConfig configures the DNS proxy.
type DNSProxyConfig struct {
	// ListenAddr is the local UDP address to bind (e.g., "127.0.0.1:5353").
	ListenAddr string
	// UpstreamDNS is the DNS server the server-side resolves to.
	UpstreamDNS string
	// Logger is an optional structured logger.
	Logger *zap.Logger
	// BypassDomains and BypassIPs mirror ProxyConfig: matching QNAMEs use direct DNS.
	BypassDomains []string
	BypassIPs     []*net.IPNet
	// DirectDNS lists UDP resolvers for bypass queries (host or host:port).
	// Empty means OS resolvers (Unix) plus 1.1.1.1:53.
	DirectDNS []string
}

// DefaultDNSProxyConfig returns sensible defaults.
func DefaultDNSProxyConfig() DNSProxyConfig {
	return DNSProxyConfig{
		ListenAddr:  "127.0.0.1:5353",
		UpstreamDNS: defaultUpstreamDNS,
	}
}

// DNSProxy forwards DNS queries through the HiVoid tunnel to prevent DNS leaks.
type DNSProxy struct {
	cfg             DNSProxyConfig
	dial            func(ctx context.Context, target string) (net.Conn, error)
	logger          *zap.Logger
	directResolvers []string

	mu   sync.Mutex
	conn *net.UDPConn
}

// NewDNSProxy creates a DNSProxy backed by the given tunnel dial function.
func NewDNSProxy(cfg DNSProxyConfig, sessDial func(ctx context.Context, target string) (net.Conn, error)) *DNSProxy {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	if cfg.UpstreamDNS == "" {
		cfg.UpstreamDNS = defaultUpstreamDNS
	}
	direct := DirectDNSResolvers(cfg.DirectDNS)
	return &DNSProxy{cfg: cfg, dial: sessDial, logger: logger, directResolvers: direct}
}

// ListenAndServe starts the DNS UDP listener and blocks until ctx is cancelled.
func (d *DNSProxy) ListenAndServe(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", d.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve dns listen addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp dns: %w", err)
	}

	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()

	fields := []zap.Field{
		zap.String("addr", d.cfg.ListenAddr),
		zap.String("tunnel_upstream", d.cfg.UpstreamDNS),
	}
	if len(d.cfg.BypassDomains) > 0 || len(d.cfg.BypassIPs) > 0 {
		fields = append(fields,
			zap.Int("bypass_domain_rules", len(d.cfg.BypassDomains)),
			zap.Int("bypass_ip_rules", len(d.cfg.BypassIPs)),
			zap.Int("direct_resolvers", len(d.directResolvers)),
		)
	}
	d.logger.Info("dns proxy listening", fields...)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, dnsMaxMsgLen)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			d.logger.Warn("dns read error", zap.Error(err))
			continue
		}

		query := make([]byte, n)
		copy(query, buf[:n])
		go d.handleQuery(ctx, conn, clientAddr, query)
	}
}

// Close stops the DNS listener.
func (d *DNSProxy) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

// handleQuery forwards a single DNS query through the tunnel and returns the response.
func (d *DNSProxy) handleQuery(ctx context.Context, udpConn *net.UDPConn, clientAddr *net.UDPAddr, query []byte) {
	qctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	if name, ok := dnsFirstQuestionName(query); ok && HostMatchesBypass(name, d.cfg.BypassDomains, d.cfg.BypassIPs) {
		for _, srv := range d.directResolvers {
			resp, err := exchangeDNSUDP(qctx, query, srv)
			if err != nil {
				d.logger.Debug("direct dns exchange failed", zap.String("server", srv), zap.String("name", name), zap.Error(err))
				continue
			}
			if _, err := udpConn.WriteToUDP(resp, clientAddr); err != nil {
				d.logger.Debug("dns udp reply failed", zap.Error(err))
			}
			return
		}
		d.logger.Debug("direct dns exhausted, using tunnel", zap.String("name", name))
	}

	// Open a tunnel to the upstream DNS server over TCP
	tunnel, err := d.dial(qctx, d.cfg.UpstreamDNS)
	if err != nil {
		d.logger.Warn("dns tunnel dial failed", zap.Error(err))
		return
	}
	defer tunnel.Close()
	tunnel.SetDeadline(time.Now().Add(dnsTimeout))

	// DNS-over-TCP framing: 2-byte big-endian length prefix, then the message
	if err := writeDNSTCP(tunnel, query); err != nil {
		d.logger.Debug("dns write failed", zap.Error(err))
		return
	}

	// Read the response
	resp, err := readDNSTCP(tunnel)
	if err != nil {
		d.logger.Debug("dns read response failed", zap.Error(err))
		return
	}

	// Return the raw DNS response to the client over UDP
	if _, err := udpConn.WriteToUDP(resp, clientAddr); err != nil {
		d.logger.Debug("dns udp reply failed", zap.Error(err))
	}
}

// writeDNSTCP writes a DNS-over-TCP message: [len:2][msg:N].
func writeDNSTCP(w io.Writer, msg []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// readDNSTCP reads a DNS-over-TCP message: [len:2][msg:N].
func readDNSTCP(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read dns length: %w", err)
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if msgLen == 0 || msgLen > dnsMaxMsgLen {
		return nil, fmt.Errorf("invalid dns message length: %d", msgLen)
	}
	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read dns body: %w", err)
	}
	return buf, nil
}

// dnsFirstQuestionName returns the QNAME from the first question (standard query, no name compression).
func dnsFirstQuestionName(msg []byte) (string, bool) {
	if len(msg) < 12 {
		return "", false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 != 0 {
		return "", false // QR: not a query
	}
	if (flags>>11)&0xF != 0 {
		return "", false // opcode: only standard QUERY
	}
	if binary.BigEndian.Uint16(msg[4:6]) < 1 {
		return "", false
	}
	off := 12
	var labels []string
	for {
		if off >= len(msg) {
			return "", false
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l > 63 || l&0xC0 != 0 {
			// Compression or extended label — fall back to tunnel path.
			return "", false
		}
		if off+l > len(msg) {
			return "", false
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	if off+4 > len(msg) {
		return "", false
	}
	return strings.Join(labels, "."), true
}
