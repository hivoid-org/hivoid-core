// Package client — DNS-over-tunnel proxy.
//
// DNSProxy listens for DNS queries on a local UDP port and forwards them
// through the HiVoid encrypted tunnel to the server, which resolves them
// using the server's own DNS resolver. This prevents DNS leaks — without
// this, DNS queries would bypass the tunnel and reveal browsing activity.
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
	cfg    DNSProxyConfig
	dial   func(ctx context.Context, target string) (net.Conn, error)
	logger *zap.Logger

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
	return &DNSProxy{cfg: cfg, dial: sessDial, logger: logger}
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

	d.logger.Info("dns proxy listening",
		zap.String("addr", d.cfg.ListenAddr),
		zap.String("upstream", d.cfg.UpstreamDNS),
	)

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
