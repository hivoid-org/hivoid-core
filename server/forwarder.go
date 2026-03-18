// Package server — TCP/UDP forwarder for HiVoid proxy mode.
//
// The Forwarder is a session.SessionHandler that accepts inbound proxy tunnel
// connections from HiVoid clients, opens TCP connections to the target, and
// relays data bidirectionally.
//
// Flow:
//
//	Client app (browser, curl…)
//	   ↓ SOCKS5 / HTTP CONNECT
//	HiVoid client proxy (client/proxy.go)
//	   ↓ FrameProxy → DialTunnel (encrypted QUIC stream)
//	HiVoid server Forwarder  ← this file
//	   ↓ TCP dial
//	Internet destination
package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hivoid-org/hivoid-core/session"
	"github.com/hivoid-org/hivoid-core/transport"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// relayBufSize is the buffer size for bidirectional relay copies.
// 256 KB matches typical TLS record sizes and reduces syscall overhead.
const relayBufSize = 256 * 1024

// ForwarderConfig configures the server-side forwarder.
type ForwarderConfig struct {
	// DialTimeout is the maximum time to dial a target host.
	DialTimeout time.Duration
	// MaxConnections limits concurrent forwarded connections (0 = unlimited).
	MaxConnections int
	// AllowedHosts is a list of allowed destination patterns ("" = all).
	AllowedHosts []string
	// BlockedHosts is a list of blocked destination patterns.
	BlockedHosts []string
	// Logger is an optional structured logger.
	Logger *zap.Logger
}

// DefaultForwarderConfig returns sensible defaults.
func DefaultForwarderConfig() ForwarderConfig {
	return ForwarderConfig{
		DialTimeout:    10 * time.Second,
		MaxConnections: 0,
	}
}

// relayBufPool is a sync.Pool for relay buffers to reduce GC pressure.
var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, relayBufSize)
		return &b
	},
}

// Forwarder is a transport.SessionHandler that proxies tunnel connections
// to their real destinations over TCP.
type Forwarder struct {
	cfg    ForwarderConfig
	logger *zap.Logger
	sem    chan struct{} // connection limit semaphore
	dialer net.Dialer
	wg     sync.WaitGroup
}

// NewForwarder creates a Forwarder with the given configuration.
func NewForwarder(cfg ForwarderConfig) *Forwarder {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	var sem chan struct{}
	if cfg.MaxConnections > 0 {
		sem = make(chan struct{}, cfg.MaxConnections)
	}

	dialer := net.Dialer{
		Timeout: cfg.DialTimeout,
	}

	return &Forwarder{cfg: cfg, logger: logger, sem: sem, dialer: dialer}
}

// Handler returns a transport.SessionHandler that forwards proxy tunnels.
func (f *Forwarder) Handler() transport.SessionHandler {
	return func(sess *session.Session) {
		ctx := sess.Connection().Context()
		log := f.logger.With(zap.String("session", sess.ID().String()))
		log.Info("proxy session started")
		defer log.Info("proxy session ended")

		for {
			// Phase 1: accept stream and read ProxyRequest
			stream, target, err := sess.AcceptTunnel(ctx)
			if err != nil {
				if ctx.Err() != nil || isSessionClosed(err) || searchStr(err.Error(), "accept tunnel stream:") {
					return
				}
				log.Warn("accept tunnel stream error, ignoring", zap.Error(err))
				continue
			}
			f.wg.Add(1)
			go f.forward(ctx, sess, stream, target, log)
		}
	}
}

// forward handles one proxied TCP connection:
//  1. Enforce limits and ACL
//  2. Dial the target
//  3. Send ProxyResponse (success or failure) to client
//  4. Wrap the stream in a TunnelConn and relay
func (f *Forwarder) forward(
	ctx context.Context,
	sess *session.Session,
	stream quic.Stream,
	target string,
	log *zap.Logger,
) {
	defer f.wg.Done()

	// Connection limit
	if f.sem != nil {
		select {
		case f.sem <- struct{}{}:
			defer func() { <-f.sem }()
		default:
			session.SendProxyErrToStream(stream, "connection limit reached")
			stream.CancelRead(quic.StreamErrorCode(0))
			stream.Close()
			log.Warn("connection limit", zap.String("target", target))
			return
		}
	}

	// ACL check
	if err := f.checkACL(target); err != nil {
		session.SendProxyErrToStream(stream, err.Error())
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		log.Warn("ACL blocked", zap.String("target", target), zap.Error(err))
		return
	}

	log.Debug("forwarding", zap.String("target", target))

	// Phase 2: dial the real TCP destination
	dialCtx, cancel := context.WithTimeout(ctx, f.cfg.DialTimeout)
	defer cancel()

	remote, err := f.dialer.DialContext(dialCtx, "tcp", target)
	if err != nil {
		session.SendProxyErrToStream(stream, fmt.Sprintf("dial %s: %s", target, err.Error()))
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		log.Warn("dial failed", zap.String("target", target), zap.Error(err))
		return
	}
	defer remote.Close()

	// Phase 3: send success response; client's DialTunnel unblocks after this
	if err := session.SendProxyOkToStream(stream); err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		log.Debug("write proxy ok failed", zap.Error(err))
		return
	}

	// Phase 4: wrap stream in encrypted TunnelConn and relay bidirectionally
	tunnel := sess.WrapTunnel(stream, target)
	defer tunnel.Close()

	log.Debug("relay started", zap.String("target", target))
	start := time.Now()
	n := biRelay(tunnel, remote)
	log.Debug("relay done",
		zap.String("target", target),
		zap.Int64("bytes", n),
		zap.Duration("duration", time.Since(start)),
	)
}

// biRelay copies data between a and b concurrently.
// Returns the total bytes transferred across both directions.
func biRelay(a, b net.Conn) int64 {
	var (
		mu    sync.Mutex
		total int64
		wg    sync.WaitGroup
	)

	add := func(n int64) {
		mu.Lock()
		total += n
		mu.Unlock()
	}

	copyDir := func(dst, src net.Conn) {
		defer wg.Done()
		bufp := relayBufPool.Get().(*[]byte)
		n, _ := io.CopyBuffer(dst, src, *bufp)
		relayBufPool.Put(bufp)
		add(n)
		// Half-close the write side so the peer knows we're done sending.
		// Works for both *net.TCPConn and TunnelConn (which has CloseWrite).
		if hc, ok := dst.(interface{ CloseWrite() error }); ok {
			hc.CloseWrite() //nolint:errcheck
		} else {
			dst.Close()
		}
	}

	wg.Add(2)
	go copyDir(a, b)
	go copyDir(b, a)
	wg.Wait()

	return total
}

// checkACL returns an error if the target is blocked or not in the allow list.
func (f *Forwarder) checkACL(target string) error {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}

	for _, pattern := range f.cfg.BlockedHosts {
		if matchHost(pattern, host) {
			return fmt.Errorf("blocked destination: %s", host)
		}
	}

	if len(f.cfg.AllowedHosts) == 0 {
		return nil
	}
	for _, pattern := range f.cfg.AllowedHosts {
		if matchHost(pattern, host) {
			return nil
		}
	}
	return fmt.Errorf("destination not in allowlist: %s", host)
}

// matchHost checks if host matches pattern. Supports "*" (everything) or
// "*.suffix" wildcard prefix patterns.
func matchHost(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if len(pattern) > 2 && pattern[:2] == "*." {
		suffix := pattern[1:]
		return len(host) > len(suffix) && host[len(host)-len(suffix):] == suffix
	}
	return pattern == host
}

func isSessionClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, sub := range []string{"session closed", "Application error", "connection closed", "EOF"} {
		if searchStr(s, sub) {
			return true
		}
	}
	return false
}

func searchStr(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Wait blocks until all active relay goroutines finish (graceful shutdown).
func (f *Forwarder) Wait() { f.wg.Wait() }
