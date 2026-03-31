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
	"sync/atomic"
	"time"

	"github.com/hivoid-org/hivoid-core/frames"
	"github.com/hivoid-org/hivoid-core/geodata"
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
	// Users defines per-user runtime policies.
	Users map[[16]byte]session.UserPolicy
	// ConnectionTracking toggles per-user connection counters.
	ConnectionTracking bool
	// UserControls tracks usage and bandwidth/expiration state.
	UserControls *UserControlManager
	// DisconnectExpired closes active tunnels when the user expires.
	DisconnectExpired bool
	// GeoIPPath is path to geoip.dat.
	GeoIPPath string
	// GeoSitePath is path to geosite.dat.
	GeoSitePath string
	// BlockedTags is a global list of blocked country codes or categories.
	BlockedTags []string
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
	logger  *zap.Logger
	dialer  net.Dialer
	wg      sync.WaitGroup
	limiter *ConnectionLimiter
	users   *UserControlManager
	runtime atomic.Value // forwarderRuntime
	geo     atomic.Value // *geodata.GeoMatcher
}

type forwarderRuntime struct {
	maxConnections     int
	allowedHosts       []string
	blockedHosts       []string
	dialTimeout        time.Duration
	users              map[[16]byte]session.UserPolicy
	connectionTracking bool
	disconnectExpired  bool
	blockedTags        []string
}

// NewForwarder creates a Forwarder with the given configuration.
func NewForwarder(cfg ForwarderConfig) *Forwarder {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	dialer := net.Dialer{
		Timeout: cfg.DialTimeout,
	}
	f := &Forwarder{
		logger:  logger,
		dialer:  dialer,
		limiter: &ConnectionLimiter{},
		users:   cfg.UserControls,
	}
	f.geo.Store(geodata.NewGeoMatcher(cfg.GeoIPPath, cfg.GeoSitePath))
	f.UpdateRuntime(cfg)
	return f
}

// UpdateRuntime atomically applies runtime changes for new forwarded connections.
func (f *Forwarder) UpdateRuntime(cfg ForwarderConfig) {
	if cfg.UserControls != nil {
		f.users = cfg.UserControls
	}
	users := make(map[[16]byte]session.UserPolicy, len(cfg.Users))
	for k, v := range cfg.Users {
		users[k] = v
	}
	rt := forwarderRuntime{
		maxConnections:     cfg.MaxConnections,
		allowedHosts:       append([]string(nil), cfg.AllowedHosts...),
		blockedHosts:       append([]string(nil), cfg.BlockedHosts...),
		dialTimeout:        cfg.DialTimeout,
		users:              users,
		connectionTracking: cfg.ConnectionTracking,
		disconnectExpired:  cfg.DisconnectExpired,
		blockedTags:        append([]string(nil), cfg.BlockedTags...),
	}
	if rt.dialTimeout <= 0 {
		rt.dialTimeout = 10 * time.Second
	}
	f.runtime.Store(rt)

	// Update GeoMatcher if paths changed
	currentGeo := f.geo.Load()
	if currentGeo == nil || cfg.GeoIPPath != "" || cfg.GeoSitePath != "" {
		f.geo.Store(geodata.NewGeoMatcher(cfg.GeoIPPath, cfg.GeoSitePath))
	}
}

// Handler returns a transport.SessionHandler that forwards proxy tunnels.
func (f *Forwarder) Handler() transport.SessionHandler {
	return func(sess *session.Session) {
		ctx := sess.Connection().Context()
		log := f.logger.With(zap.String("session", sess.ID().String()))
		userUUID := sess.ClientUUID()

		rt := f.runtime.Load().(forwarderRuntime)
		userPolicy, hasUserPolicy := rt.users[userUUID]
		limit := rt.maxConnections
		if hasUserPolicy && userPolicy.MaxConnections > 0 {
			limit = userPolicy.MaxConnections
		}

		if rt.connectionTracking || limit > 0 {
			active, ok := f.limiter.TryAcquire(userUUID, limit)
			if !ok {
				log.Warn("session limit reached for user",
					zap.String("uuid", fmt.Sprintf("%x", userUUID)),
					zap.Int("limit", limit),
				)
				sess.Close() // Reject the entire device connection
				return
			}
			defer func() {
				remaining := f.limiter.Release(userUUID)
				log.Debug("session connection released", zap.Int64("active", remaining))
			}()
			log.Info("new session accepted (device connected)",
				zap.Int("limit", limit),
				zap.Int64("active", active),
			)
		}
		// ------------------------------------------------------------------------------

		log.Info("proxy session loop started")
		defer log.Info("proxy session loop ended")

		for {
			// Phase 1: accept stream and read ProxyRequest
			stream, req, err := sess.AcceptTunnel(ctx)
			if err != nil {
				if ctx.Err() != nil || isSessionClosed(err) || searchStr(err.Error(), "accept tunnel stream:") {
					return
				}
				log.Warn("accept tunnel stream error, ignoring", zap.Error(err))
				continue
			}
			f.wg.Add(1)
			go f.forward(ctx, sess, stream, req, log)
		}
	}
}

// forward handles one proxied connection (TCP or UDP):
func (f *Forwarder) forward(
	ctx context.Context,
	sess *session.Session,
	stream *quic.Stream,
	req *frames.ProxyRequest,
	log *zap.Logger,
) {
	defer f.wg.Done()
	target := req.Target()
	rt := f.runtime.Load().(forwarderRuntime)
	userUUID := sess.ClientUUID()
	userPolicy, hasUserPolicy := rt.users[userUUID]

	if f.users != nil {
		if err := f.users.AllowNewConnection(userUUID); err != nil {
			session.SendProxyError(stream, err.Error())
			stream.CancelRead(quic.StreamErrorCode(0))
			_ = stream.Close()
			log.Warn("user policy reject", zap.String("target", target), zap.Error(err))
			return
		}
	}

	// ACL check
	if err := f.checkACL(rt, userPolicy, target); err != nil {
		session.SendProxyError(stream, err.Error())
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		log.Warn("ACL blocked", zap.String("target", target), zap.Error(err))
		return
	}

	if req.Protocol == 0x02 { // UDP
		f.forwardUDP(ctx, sess, stream, req, log)
		return
	}

	log.Debug("forwarding TCP", zap.String("target", target))

	// Phase 2: dial the real TCP destination
	dialCtx, cancel := context.WithTimeout(ctx, rt.dialTimeout)
	defer cancel()

	// Handle BindIP if set
	dialer := f.dialer
	if hasUserPolicy && userPolicy.BindIP != "" {
		ip := net.ParseIP(userPolicy.BindIP)
		if ip != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}

	remote, err := dialer.DialContext(dialCtx, "tcp", target)
	if err != nil {
		session.SendProxyError(stream, fmt.Sprintf("dial %s: %s", target, err.Error()))
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		log.Warn("dial failed", zap.String("target", target), zap.Error(err))
		return
	}
	defer remote.Close()

	// Phase 3: send success response; client's DialTunnel unblocks after this
	if err := session.SendProxyOK(stream); err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		log.Debug("write proxy ok failed", zap.Error(err))
		return
	}

	// Phase 4: wrap stream in encrypted TunnelConn and relay bidirectionally
	tunnel := sess.WrapTunnel(stream, target)
	defer tunnel.Close()

	log.Debug("relay started", zap.String("target", target))
	start := time.Now()
	n := f.biRelay(tunnel, remote, userUUID, rt.disconnectExpired)
	if f.users != nil {
		in, out := f.users.UserUsage(userUUID)
		log.Debug("user traffic totals",
			zap.Uint64("bytes_in", in),
			zap.Uint64("bytes_out", out),
			zap.Uint64("total_usage", in+out),
		)
	}
	log.Debug("relay done",
		zap.String("target", target),
		zap.Int64("bytes", n),
		zap.Duration("duration", time.Since(start)),
	)
}

func (f *Forwarder) forwardUDP(
	ctx context.Context,
	sess *session.Session,
	stream *quic.Stream,
	req *frames.ProxyRequest,
	log *zap.Logger,
) {
	target := req.Target()
	log.Debug("forwarding UDP", zap.String("target", target))
	rt := f.runtime.Load().(forwarderRuntime)
	userUUID := sess.ClientUUID()

	// Dial UDP
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		session.SendProxyError(stream, fmt.Sprintf("resolve %s: %s", target, err.Error()))
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return
	}

	var localAddr *net.UDPAddr
	userPolicy, ok := rt.users[userUUID]
	if ok && userPolicy.BindIP != "" {
		ip := net.ParseIP(userPolicy.BindIP)
		if ip != nil {
			localAddr = &net.UDPAddr{IP: ip}
		}
	}

	remote, err := net.DialUDP("udp", localAddr, addr)
	if err != nil {
		session.SendProxyError(stream, fmt.Sprintf("dial udp %s: %s", target, err.Error()))
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		log.Warn("dial udp failed", zap.String("target", target), zap.Error(err))
		return
	}
	defer remote.Close()

	if err := session.SendProxyOK(stream); err != nil {
		_ = stream.Close()
		return
	}

	tunnel := sess.WrapTunnel(stream, target)
	defer tunnel.Close()

	// Relay UDP packets
	// Note: We use length-prefixing on the QUIC stream to carry UDP packets.
	f.biRelayUDP(tunnel, remote, userUUID, rt.disconnectExpired)
}

func (f *Forwarder) biRelayUDP(tunnel net.Conn, remote *net.UDPConn, userUUID [16]byte, disconnectExpired bool) {
	var wg sync.WaitGroup
	wg.Add(2)

	// User Tunnel -> Remote (Upload)
	go func() {
		defer wg.Done()
		header := make([]byte, 2)
		for {
			if _, err := io.ReadFull(tunnel, header); err != nil {
				return
			}
			n := int(header[0])<<8 | int(header[1])
			if n > 65535 || n < 0 {
				return
			}
			pkt := make([]byte, n)
			if _, err := io.ReadFull(tunnel, pkt); err != nil {
				return
			}

			if f.users != nil {
				if disconnectExpired && f.users.IsExpired(userUUID) {
					return
				}
				f.users.Throttle(userUUID, n)
				f.users.AddBytesOut(userUUID, uint64(n))
			}
			_, _ = remote.Write(pkt)
		}
	}()

	// Remote -> User Tunnel (Download)
	go func() {
		defer wg.Done()
		pkt := make([]byte, 65535)
		header := make([]byte, 2)
		for {
			n, err := remote.Read(pkt)
			if err != nil {
				return
			}
			if n <= 0 {
				continue
			}

			header[0] = byte(n >> 8)
			header[1] = byte(n)
			if _, err := tunnel.Write(header); err != nil {
				return
			}
			if _, err := tunnel.Write(pkt[:n]); err != nil {
				return
			}

			if f.users != nil {
				f.users.AddBytesIn(userUUID, uint64(n))
			}
		}
	}()

	wg.Wait()
}

// biRelay copies data between a and b concurrently.
// Returns the total bytes transferred across both directions.
func (f *Forwarder) biRelay(a, b net.Conn, userUUID [16]byte, disconnectExpired bool) int64 {
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

	copyDir := func(dst, src net.Conn, isDownload bool) {
		defer wg.Done()
		bufp := relayBufPool.Get().(*[]byte)
		buf := *bufp
		n, _ := f.relayWithControls(dst, src, buf, userUUID, isDownload, disconnectExpired)
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
	go copyDir(a, b, true)  // remote -> user tunnel = bytes_in (download)
	go copyDir(b, a, false) // user tunnel -> remote = bytes_out (upload)
	wg.Wait()

	return total
}

func (f *Forwarder) relayWithControls(
	dst net.Conn,
	src net.Conn,
	buf []byte,
	userUUID [16]byte,
	isDownload bool,
	disconnectExpired bool,
) (int64, error) {
	var total int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			chunk := buf[:nr]
			if f.users != nil {
				if disconnectExpired && f.users.IsExpired(userUUID) {
					return total, fmt.Errorf("user expired")
				}
				f.users.Throttle(userUUID, nr)
			}
			written := 0
			for written < nr {
				nw, ew := dst.Write(chunk[written:])
				if nw > 0 {
					written += nw
					total += int64(nw)
					if f.users != nil {
						if isDownload {
							f.users.AddBytesIn(userUUID, uint64(nw))
						} else {
							f.users.AddBytesOut(userUUID, uint64(nw))
						}
					}
				}
				if ew != nil {
					return total, ew
				}
				if nw == 0 {
					return total, io.ErrShortWrite
				}
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

// checkACL returns an error if the target is blocked or not in the allow list.
func (f *Forwarder) checkACL(rt forwarderRuntime, p session.UserPolicy, target string) error {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}

	geo := f.geo.Load().(*geodata.GeoMatcher)

	// 1. Global Blocking
	for _, pattern := range rt.blockedHosts {
		if matchHost(pattern, host) {
			return fmt.Errorf("blocked destination (global): %s", host)
		}
	}
	if geo != nil && geo.Match(host, rt.blockedTags) {
		return fmt.Errorf("blocked category/country (global): %s", host)
	}

	// 2. Per-User Blocking (Explicit Hosts)
	for _, pattern := range p.BlockedHosts {
		if matchHost(pattern, host) {
			return fmt.Errorf("blocked destination (user): %s", host)
		}
	}

	// 3. Per-User Blocking (Geo Tags/Countries/Categories)
	if geo != nil && geo.Match(host, p.BlockedTags) {
		return fmt.Errorf("blocked category/country (user): %s", host)
	}

	// 4. Global Allowlist (if non-empty)
	if len(rt.allowedHosts) == 0 {
		return nil
	}
	for _, pattern := range rt.allowedHosts {
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
