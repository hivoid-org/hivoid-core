// Package client — SOCKS5 and HTTP CONNECT proxy server.
//
// ProxyServer listens on a local TCP port and accepts connections from
// any SOCKS5 or HTTP-aware application (browser, curl, etc.). Each
// connection is forwarded through the HiVoid tunnel to the server, which
// opens the actual TCP connection to the destination.
//
// SOCKS5 implementation follows RFC 1928 (authentication) and RFC 1929
// (username/password auth, currently unused — we default to no-auth).
//
// HTTP proxy supports both:
//   - CONNECT method: tunnels arbitrary TCP (HTTPS, SSH, etc.)
//   - Regular GET/POST: transparently forwards HTTP requests
package client

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hivoid-org/hivoid-core/session"
	"go.uber.org/zap"
)

// ProxyConfig configures the local proxy listener.
type ProxyConfig struct {
	// ListenAddr is the [host]:port to bind the SOCKS5 / HTTP proxy.
	ListenAddr string
	// EnableSOCKS5 enables the SOCKS5 listener (recommended).
	EnableSOCKS5 bool
	// EnableHTTP enables the HTTP CONNECT proxy listener.
	EnableHTTP bool
	// Logger is an optional structured logger.
	Logger *zap.Logger
}

// DefaultProxyConfig returns sensible defaults.
func DefaultProxyConfig() ProxyConfig {
	return ProxyConfig{
		ListenAddr:   "127.0.0.1:1080",
		EnableSOCKS5: true,
		EnableHTTP:   true,
	}
}

// ProxyServer listens for SOCKS5 / HTTP proxy connections and routes them
// through the active HiVoid session.
type ProxyServer struct {
	cfg     ProxyConfig
	logger  *zap.Logger
	getConn func(ctx context.Context, target string) (net.Conn, error)

	mu       sync.Mutex
	listener net.Listener
}

// NewProxyServer creates a ProxyServer.
//
// dialFunc is called for each new proxied connection; it should forward
// the connection through the HiVoid session (e.g., sess.DialTunnel).
func NewProxyServer(cfg ProxyConfig, dialFunc func(ctx context.Context, target string) (net.Conn, error)) *ProxyServer {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	return &ProxyServer{
		cfg:     cfg,
		logger:  logger,
		getConn: dialFunc,
	}
}

// ListenAndServe starts the proxy listener and blocks until ctx is cancelled.
func (p *ProxyServer) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("proxy listen on %s: %w", p.cfg.ListenAddr, err)
	}

	p.mu.Lock()
	p.listener = ln
	p.mu.Unlock()

	p.logger.Info("proxy listening", zap.String("addr", p.cfg.ListenAddr))

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			p.logger.Warn("accept error", zap.Error(err))
			continue
		}
		go p.dispatch(ctx, conn)
	}
}

// Close stops the listener.
func (p *ProxyServer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// dispatch detects whether the connection is SOCKS5 or HTTP and handles it.
func (p *ProxyServer) dispatch(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Peek the first byte to distinguish SOCKS5 (0x05) from HTTP
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	conn.SetDeadline(time.Time{}) // clear deadline after detection

	if buf[0] == 0x05 {
		p.handleSOCKS5(ctx, conn)
	} else {
		// HTTP — prepend the peeked byte back using a multi-reader
		multi := io.MultiReader(strings.NewReader(string(buf)), conn)
		p.handleHTTP(ctx, conn, multi)
	}
}

// ─── SOCKS5 ──────────────────────────────────────────────────────────────────

const (
	socks5Version            = 0x05
	socks5CmdConnect         = 0x01
	socks5AuthNoAuth         = 0x00
	socks5AuthNoAcceptable   = 0xFF
	socks5AddrIPv4           = 0x01
	socks5AddrDomain         = 0x03
	socks5AddrIPv6           = 0x04
	socks5RepSuccess         = 0x00
	socks5RepFailure         = 0x01
	socks5RepNotAllowed      = 0x02
	socks5RepHostUnreachable = 0x04
	socks5RepCmdNotSupported = 0x07
)

// handleSOCKS5 processes a SOCKS5 connection.
//
// Protocol:
//  1. Client→Proxy: version + auth methods
//  2. Proxy→Client: selected auth (no-auth)
//  3. Client→Proxy: CONNECT request with target address
//  4. Proxy→Client: success/failure reply
//  5. Data relay
func (p *ProxyServer) handleSOCKS5(ctx context.Context, conn net.Conn) {
	// Step 1: Read method selection
	// Already consumed version byte (0x05) in dispatch; read nmethods
	var nmethods [1]byte
	if _, err := io.ReadFull(conn, nmethods[:]); err != nil {
		return
	}
	methods := make([]byte, nmethods[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Step 2: Reply with no-auth (0x00)
	hasNoAuth := false
	for _, m := range methods {
		if m == socks5AuthNoAuth {
			hasNoAuth = true
		}
	}
	if !hasNoAuth {
		conn.Write([]byte{socks5Version, socks5AuthNoAcceptable}) //nolint:errcheck
		return
	}
	if _, err := conn.Write([]byte{socks5Version, socks5AuthNoAuth}); err != nil {
		return
	}

	// Step 3: Read CONNECT request
	// [ver:1][cmd:1][rsv:1][atyp:1][addr...][port:2]
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socks5Version || header[1] != socks5CmdConnect {
		p.socks5Reply(conn, socks5RepCmdNotSupported, "0.0.0.0", 0)
		return
	}

	var target string
	switch header[3] {
	case socks5AddrIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		target = fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
	case socks5AddrDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		domainBytes := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBytes); err != nil {
			return
		}
		target = string(domainBytes)
	case socks5AddrIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		target = net.IP(addr).String()
	default:
		p.socks5Reply(conn, socks5RepCmdNotSupported, "0.0.0.0", 0)
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	target = fmt.Sprintf("%s:%d", target, port)

	p.logger.Debug("SOCKS5 CONNECT", zap.String("target", target))

	// Step 4: Connect through HiVoid tunnel
	tunnelConn, err := p.getConn(ctx, target)
	if err != nil {
		p.logger.Warn("tunnel dial failed", zap.String("target", target), zap.Error(err))
		p.socks5Reply(conn, socks5RepHostUnreachable, "0.0.0.0", 0)
		return
	}
	defer tunnelConn.Close()

	// Reply success
	p.socks5Reply(conn, socks5RepSuccess, "0.0.0.0", 0)

	// Step 5: Bidirectional relay
	relay(conn, tunnelConn)
}

// socks5Reply sends a SOCKS5 reply to the client.
func (p *ProxyServer) socks5Reply(conn net.Conn, rep uint8, bindAddr string, bindPort uint16) {
	ip := net.ParseIP(bindAddr).To4()
	if ip == nil {
		ip = []byte{0, 0, 0, 0}
	}
	reply := []byte{
		socks5Version, rep, 0x00, socks5AddrIPv4,
		ip[0], ip[1], ip[2], ip[3],
		byte(bindPort >> 8), byte(bindPort),
	}
	conn.Write(reply) //nolint:errcheck
}

// ─── HTTP Proxy ───────────────────────────────────────────────────────────────

// handleHTTP processes an HTTP or HTTP CONNECT proxy connection.
func (p *ProxyServer) handleHTTP(ctx context.Context, conn net.Conn, r io.Reader) {
	br := bufio.NewReader(r)

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	p.logger.Debug("HTTP proxy", zap.String("method", req.Method), zap.String("host", req.Host))

	if req.Method == http.MethodConnect {
		p.handleHTTPConnect(ctx, conn, req)
	} else {
		p.handleHTTPRequest(ctx, conn, req)
	}
}

// handleHTTPConnect handles the HTTP CONNECT tunnelling method.
func (p *ProxyServer) handleHTTPConnect(ctx context.Context, conn net.Conn, req *http.Request) {
	target := req.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	tunnelConn, err := p.getConn(ctx, target)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 503 Service Unavailable\r\n\r\n")
		return
	}
	defer tunnelConn.Close()

	// Inform the client that the tunnel is established
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	relay(conn, tunnelConn)
}

// handleHTTPRequest handles a plain HTTP proxy request (non-CONNECT).
// Re-sends the request to the server via tunnel and relays the response.
func (p *ProxyServer) handleHTTPRequest(ctx context.Context, conn net.Conn, req *http.Request) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	tunnelConn, err := p.getConn(ctx, host)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 503 Service Unavailable\r\n\r\n")
		return
	}
	defer tunnelConn.Close()

	// Forward the original request
	if err := req.Write(tunnelConn); err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}

	// Relay response back to client
	relay(conn, tunnelConn)
}

// ─── Bidirectional relay ─────────────────────────────────────────────────────

// relayBufSize is the copy buffer size for relay I/O (256 KB).
const relayBufSize = 256 * 1024

var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, relayBufSize)
		return &b
	},
}

// relay copies data between two connections concurrently until both sides close.
// It uses pooled 256 KB buffers to reduce allocation overhead.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		bufp := relayBufPool.Get().(*[]byte)
		io.CopyBuffer(dst, src, *bufp) //nolint:errcheck
		relayBufPool.Put(bufp)
		// Half-close the write side so the peer knows we're done sending.
		// Works for both *net.TCPConn and TunnelConn (which has CloseWrite).
		if hc, ok := dst.(interface{ CloseWrite() error }); ok {
			hc.CloseWrite() //nolint:errcheck
		} else {
			dst.Close()
		}
	}

	go copy(a, b)
	go copy(b, a)
	wg.Wait()
}

// ─── Proxy dial helper ────────────────────────────────────────────────────────

// SessionDial returns a dialer function that routes connections through
// the given HiVoid session. Used as the dialFunc parameter of NewProxyServer.
func SessionDial(sess *session.Session) func(ctx context.Context, target string) (net.Conn, error) {
	return func(ctx context.Context, target string) (net.Conn, error) {
		return sess.DialTunnel(ctx, target)
	}
}
