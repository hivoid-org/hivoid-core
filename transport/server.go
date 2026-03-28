// Package transport — HiVoid QUIC server.
// Listens for incoming QUIC connections, performs TLS + hybrid handshakes,
// and dispatches sessions to the application handler.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/session"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// SessionHandler is a callback invoked for each successfully established session.
// Implementations should run in their own goroutine as the call blocks until
// the session is closed.
type SessionHandler func(s *session.Session)

type certReloader struct {
	cert atomic.Value // tls.Certificate
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{}
	if err := r.Reload(certFile, keyFile); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) Reload(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	r.cert.Store(cert)
	return nil
}

func (r *certReloader) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"hivoid/1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			v := r.cert.Load()
			if v == nil {
				return nil, fmt.Errorf("no certificate loaded")
			}
			c := v.(tls.Certificate)
			return &c, nil
		},
	}
}

// Server is the HiVoid QUIC server.
type Server struct {
	mu         sync.RWMutex
	listenAddr string
	certFile   string
	keyFile    string
	mode       intelligence.Mode
	logger     *zap.Logger
	manager    *session.Manager
	handler    SessionHandler

	tlsReloader *certReloader
	tlsCfg      *tls.Config
	listeners   map[string]*quic.Listener

	antiProbe    bool
	fallbackAddr string

	serveMu   sync.Mutex
	serveCtx  context.Context
	serving   bool
	acceptWg  sync.WaitGroup
}

// ServerConfig holds server startup options.
type ServerConfig struct {
	// ListenAddr is "[host]:port" to listen on.
	ListenAddr string
	// CertFile is path to the PEM TLS certificate.
	CertFile string
	// KeyFile is path to the PEM TLS private key.
	KeyFile string
	// Mode is the default operating mode for sessions.
	Mode intelligence.Mode
	// Logger is an optional structured logger.
	Logger *zap.Logger
	// Handler is called for each new session in a separate goroutine.
	Handler SessionHandler
	// AllowedUUIDs is the server-side UUID allowlist. If non-empty, only
	AllowedUUIDs [][16]byte
	// AntiProbe enables active probing defense (tarpitting scanners).
	AntiProbe bool
	// FallbackAddr is the address to proxy unrecognized traffic to (if supported).
	FallbackAddr string
}

// NewServer creates a new HiVoid server.
func NewServer(cfg ServerConfig) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	mgr := session.NewManager(false, cfg.Mode, logger)
	if len(cfg.AllowedUUIDs) > 0 {
		mgr.SetAllowedUUIDs(cfg.AllowedUUIDs)
	}
	return &Server{
		listenAddr:   cfg.ListenAddr,
		certFile:     cfg.CertFile,
		keyFile:      cfg.KeyFile,
		mode:         cfg.Mode,
		logger:       logger,
		manager:      mgr,
		handler:      cfg.Handler,
		listeners:    make(map[string]*quic.Listener),
		antiProbe:    cfg.AntiProbe,
		fallbackAddr: cfg.FallbackAddr,
	}
}

func (srv *Server) createListener(addr string) (*quic.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen addr: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	_ = udpConn.SetReadBuffer(4 * 1024 * 1024)
	_ = udpConn.SetWriteBuffer(4 * 1024 * 1024)

	transport := &quic.Transport{Conn: udpConn}
	listener, err := transport.Listen(srv.tlsCfg, QUICConfig())
	if err != nil {
		return nil, fmt.Errorf("quic listen: %w", err)
	}
	return listener, nil
}

func (srv *Server) startAcceptLoop(addr string, listener *quic.Listener) {
	srv.acceptWg.Add(1)
	go func() {
		defer srv.acceptWg.Done()
		for {
			srv.serveMu.Lock()
			ctx := srv.serveCtx
			srv.serveMu.Unlock()
			if ctx == nil {
				return
			}
			conn, err := listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// Listener closed during reload.
				srv.mu.RLock()
				_, stillActive := srv.listeners[addr]
				srv.mu.RUnlock()
				if !stillActive {
					return
				}
				srv.logger.Warn("accept error", zap.String("addr", addr), zap.Error(err))
				continue
			}
			go srv.handleConn(ctx, conn)
		}
	}()
}

// Listen binds the UDP port and starts the initial QUIC listener.
func (srv *Server) Listen() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.tlsReloader == nil {
		reloader, err := newCertReloader(srv.certFile, srv.keyFile)
		if err != nil {
			return fmt.Errorf("load TLS config: %w", err)
		}
		srv.tlsReloader = reloader
		srv.tlsCfg = reloader.TLSConfig()
	}
	if _, exists := srv.listeners[srv.listenAddr]; exists {
		return nil
	}

	listener, err := srv.createListener(srv.listenAddr)
	if err != nil {
		return err
	}
	srv.listeners[srv.listenAddr] = listener
	srv.logger.Info("listening", zap.String("addr", srv.listenAddr))
	return nil
}

// Serve begins accepting QUIC connections. It blocks until ctx is cancelled.
func (srv *Server) Serve(ctx context.Context) error {
	srv.mu.RLock()
	if len(srv.listeners) == 0 {
		srv.mu.RUnlock()
		return fmt.Errorf("call Listen() before Serve()")
	}
	pairs := make([]struct {
		addr string
		l    *quic.Listener
	}, 0, len(srv.listeners))
	for addr, l := range srv.listeners {
		pairs = append(pairs, struct {
			addr string
			l    *quic.Listener
		}{addr: addr, l: l})
	}
	srv.mu.RUnlock()

	srv.serveMu.Lock()
	srv.serveCtx = ctx
	srv.serving = true
	srv.serveMu.Unlock()

	for _, p := range pairs {
		srv.startAcceptLoop(p.addr, p.l)
	}

	<-ctx.Done()
	srv.serveMu.Lock()
	srv.serving = false
	srv.serveCtx = nil
	srv.serveMu.Unlock()
	srv.acceptWg.Wait()
	return nil
}

// ListenAndServe is a convenience helper that calls Listen then Serve.
func (srv *Server) ListenAndServe(ctx context.Context) error {
	if err := srv.Listen(); err != nil {
		return err
	}
	return srv.Serve(ctx)
}

// ReloadConfig applies listener/certificate updates live.
// This enables full server-side hot reload without process restart.
func (srv *Server) ReloadConfig(cfg ServerConfig) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.tlsReloader == nil {
		reloader, err := newCertReloader(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("load TLS config: %w", err)
		}
		srv.tlsReloader = reloader
		srv.tlsCfg = reloader.TLSConfig()
	} else if cfg.CertFile != srv.certFile || cfg.KeyFile != srv.keyFile {
		if err := srv.tlsReloader.Reload(cfg.CertFile, cfg.KeyFile); err != nil {
			return fmt.Errorf("reload TLS cert/key: %w", err)
		}
	}

	if cfg.ListenAddr == "" {
		return fmt.Errorf("listen address is empty")
	}

	// Ensure new listener exists and starts first.
	if _, exists := srv.listeners[cfg.ListenAddr]; !exists {
		l, err := srv.createListener(cfg.ListenAddr)
		if err != nil {
			return err
		}
		srv.listeners[cfg.ListenAddr] = l
		srv.logger.Info("listener added", zap.String("addr", cfg.ListenAddr))

		srv.serveMu.Lock()
		serving := srv.serving
		srv.serveMu.Unlock()
		if serving {
			srv.startAcceptLoop(cfg.ListenAddr, l)
		}
	}

	// Remove old listeners only after new endpoint is active.
	for addr, l := range srv.listeners {
		if addr == cfg.ListenAddr {
			continue
		}
		delete(srv.listeners, addr)
		_ = l.Close()
		srv.logger.Info("listener removed", zap.String("addr", addr))
	}

	srv.listenAddr = cfg.ListenAddr
	srv.certFile = cfg.CertFile
	srv.keyFile = cfg.KeyFile
	srv.antiProbe = cfg.AntiProbe
	srv.fallbackAddr = cfg.FallbackAddr
	if cfg.Logger != nil {
		srv.logger = cfg.Logger
	}
	return nil
}

// Manager returns the session manager.
func (srv *Server) Manager() *session.Manager {
	return srv.manager
}

// Close shuts down listeners and all sessions.
func (srv *Server) Close() error {
	srv.mu.Lock()
	listeners := make([]*quic.Listener, 0, len(srv.listeners))
	for _, l := range srv.listeners {
		listeners = append(listeners, l)
	}
	srv.listeners = make(map[string]*quic.Listener)
	srv.mu.Unlock()

	for _, l := range listeners {
		_ = l.Close()
	}
	srv.manager.CloseAll()
	return nil
}

// handleConn runs the server-side handshake and invokes the session handler.
func (srv *Server) handleConn(ctx context.Context, conn *quic.Conn) {
	remote := conn.RemoteAddr().String()
	srv.logger.Info("new connection", zap.String("remote", remote))

	sess, err := srv.manager.AcceptAndHandshake(ctx, conn)
	if err != nil {
		if srv.antiProbe && (errors.Is(err, session.ErrHandshakeTimeout) || errors.Is(err, session.ErrInvalidFrame)) {
			srv.logger.Warn("active probe detected, tarpitting connection", zap.String("remote", remote), zap.Error(err))
			// Tarpit the scanner: don't close the connection gracefully.
			// Let it linger until the QUIC idle timeout kills it, wasting the scanner's resources.
			return
		}

		srv.logger.Error("handshake failed",
			zap.String("remote", remote),
			zap.Error(err),
		)
		_ = conn.CloseWithError(1, "handshake failed")
		return
	}

	defer srv.manager.Remove(sess.ID())

	if srv.handler != nil {
		srv.handler(sess)
	} else {
		srv.echoHandler(ctx, sess)
	}
}

// echoHandler is the default server-side session handler.
func (srv *Server) echoHandler(ctx context.Context, sess *session.Session) {
	for {
		data, err := sess.RecvStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			srv.logger.Debug("recv error", zap.String("session", sess.ID().String()), zap.Error(err))
			return
		}

		srv.logger.Debug("echo",
			zap.String("session", sess.ID().String()),
			zap.Int("bytes", len(data)),
		)

		if err := sess.SendStream(ctx, data); err != nil {
			srv.logger.Debug("send error", zap.String("session", sess.ID().String()), zap.Error(err))
			return
		}
	}
}
