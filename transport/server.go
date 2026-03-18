// Package transport — HiVoid QUIC server.
// Listens for incoming QUIC connections, performs TLS + hybrid handshakes,
// and dispatches sessions to the application handler.
package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/session"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// SessionHandler is a callback invoked for each successfully established session.
// Implementations should run in their own goroutine as the call blocks until
// the session is closed.
type SessionHandler func(s *session.Session)

// Server is the HiVoid QUIC server.
type Server struct {
	listenAddr string
	certFile   string
	keyFile    string
	mode       intelligence.Mode
	logger     *zap.Logger
	manager    *session.Manager
	handler    SessionHandler
	listener   *quic.Listener
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
	// clients whose UUID exactly matches one of these values are accepted.
	AllowedUUIDs [][16]byte
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
		listenAddr: cfg.ListenAddr,
		certFile:   cfg.CertFile,
		keyFile:    cfg.KeyFile,
		mode:       cfg.Mode,
		logger:     logger,
		manager:    mgr,
		handler:    cfg.Handler,
	}
}

// Listen binds the UDP port and starts the QUIC listener.
// Call Serve() after this to begin accepting connections.
func (srv *Server) Listen() error {
	tlsCfg, err := ServerTLSConfig(srv.certFile, srv.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS config: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", srv.listenAddr)
	if err != nil {
		return fmt.Errorf("resolve listen addr: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}

	// Increase OS UDP buffers for high-throughput QUIC
	_ = udpConn.SetReadBuffer(4 * 1024 * 1024)
	_ = udpConn.SetWriteBuffer(4 * 1024 * 1024)

	transport := &quic.Transport{
		Conn: udpConn,
	}

	listener, err := transport.Listen(tlsCfg, QUICConfig())
	if err != nil {
		return fmt.Errorf("quic listen: %w", err)
	}

	srv.listener = listener
	srv.logger.Info("listening", zap.String("addr", srv.listenAddr))
	return nil
}

// Serve begins accepting QUIC connections. It blocks until ctx is cancelled.
// Each accepted connection is handed off to a goroutine for handshaking and
// then to the configured SessionHandler.
func (srv *Server) Serve(ctx context.Context) error {
	if srv.listener == nil {
		return fmt.Errorf("call Listen() before Serve()")
	}

	for {
		conn, err := srv.listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful shutdown
			}
			srv.logger.Error("accept error", zap.Error(err))
			return err
		}

		go srv.handleConn(ctx, conn)
	}
}

// ListenAndServe is a convenience helper that calls Listen then Serve.
func (srv *Server) ListenAndServe(ctx context.Context) error {
	if err := srv.Listen(); err != nil {
		return err
	}
	return srv.Serve(ctx)
}

// Manager returns the session manager.
func (srv *Server) Manager() *session.Manager {
	return srv.manager
}

// Close shuts down the listener and all sessions.
func (srv *Server) Close() error {
	srv.manager.CloseAll()
	if srv.listener != nil {
		return srv.listener.Close()
	}
	return nil
}

// handleConn runs the server-side handshake and invokes the session handler.
func (srv *Server) handleConn(ctx context.Context, conn quic.Connection) {
	remote := conn.RemoteAddr().String()
	srv.logger.Info("new connection", zap.String("remote", remote))

	sess, err := srv.manager.AcceptAndHandshake(ctx, conn)
	if err != nil {
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
		// Default echo handler for testing
		srv.echoHandler(ctx, sess)
	}
}

// echoHandler is the default server-side session handler.
// It reads data from the session and echoes it back — useful for testing.
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
