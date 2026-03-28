package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hivoid-org/hivoid-core/config"
	"github.com/hivoid-org/hivoid-core/session"
	"github.com/hivoid-org/hivoid-core/transport"
	"go.uber.org/zap"
)

// SessionPool manages a pool of independent QUIC sessions (connections).
// This mitigates single-connection UDP bandwidth throttling by the ISP.
type SessionPool struct {
	cfg      *config.Config
	logger   *zap.Logger
	dialer   *transport.Client
	size     int
	sessions []*session.Session
	mu       sync.RWMutex
	idx      uint64
	closed   int32
}

// NewSessionPool initializes and connects a pool of QUIC sessions.
func NewSessionPool(ctx context.Context, cfg *config.Config, c *transport.Client, logger *zap.Logger) (*SessionPool, error) {

	size := cfg.PoolSize
	if size <= 0 {
		size = config.DefaultPoolSize
	}

	p := &SessionPool{
		cfg:      cfg,
		logger:   logger,
		dialer:   c,
		size:     size,
		sessions: make([]*session.Session, size),
	}

	// Initial connect for all slots. We tolerate failures and retry in background.
	for i := 0; i < size; i++ {
		sess, err := c.Connect(ctx)
		if err != nil {
			logger.Warn("pool: failed to dial initial session, will retry", zap.Int("slot", i), zap.Error(err))
		} else {
			p.sessions[i] = sess
			logger.Debug("pool: session established", zap.Int("slot", i))
		}
	}

	// Verify at least one session is up initially to throw connection error quickly if network is down
	if !p.hasActive() {
		return nil, fmt.Errorf("initial connection failed for all %d pool slots", size)
	}

	go p.keepaliveLoop()

	return p, nil
}

// hasActive checks if there is at least one active session without locking.
func (p *SessionPool) hasActive() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, s := range p.sessions {
		if s != nil {
			return true
		}
	}
	return false
}

// DialTunnel round-robins across the active sessions to open a new tunnel.
func (p *SessionPool) DialTunnel(ctx context.Context, target string, isUDP bool) (net.Conn, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	startIdx := atomic.AddUint64(&p.idx, 1) % uint64(p.size)
	for i := 0; i < p.size; i++ {
		idx := (startIdx + uint64(i)) % uint64(p.size)
		sess := p.sessions[idx]
		if sess != nil {
			var conn net.Conn
			var err error
			if isUDP {
				conn, err = sess.DialUDPTunnel(ctx, target)
			} else {
				conn, err = sess.DialTunnel(ctx, target)
			}
			if err == nil {
				return conn, nil
			}
			// If error is network related, maybe log, but continue to next
			p.logger.Debug("pool: session OpenTunnel failed", zap.Uint64("slot", idx), zap.Error(err))
		}
	}

	return nil, fmt.Errorf("no healthy session in pool to handle request")
}

// keepaliveLoop periodically checks session health and reconnects dropped ones.
func (p *SessionPool) keepaliveLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		if atomic.LoadInt32(&p.closed) == 1 {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		p.mu.Lock()
		for i := 0; i < p.size; i++ {
			sess := p.sessions[i]
			// Check if session is nil or underlying connection is dead
			// since quic-go context is cancelled when connection drops.
			if sess == nil || sess.Connection().Context().Err() != nil {
				// Slot is dead. Reconnect.
				p.logger.Info("pool: reconnecting dropped session", zap.Int("slot", i))
				newSess, err := p.dialer.Connect(ctx)
				if err != nil {
					p.logger.Warn("pool: reconnect failed", zap.Int("slot", i), zap.Error(err))
					p.sessions[i] = nil
				} else {
					p.logger.Info("pool: session re-established", zap.Int("slot", i))
					p.sessions[i] = newSess
				}
			}
		}
		p.mu.Unlock()
		cancel()
	}
}

// Close closes all sessions and stops the keepalive loop.
func (p *SessionPool) Close() {
	atomic.StoreInt32(&p.closed, 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, s := range p.sessions {
		if s != nil {
			_ = s.Close()
			p.sessions[i] = nil
		}
	}
}
