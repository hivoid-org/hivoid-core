// Package transport — HiVoid QUIC client.
// Handles connection establishment, TLS handshake, and session lifecycle.
package transport

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/obfuscation"
	"github.com/hivoid-org/hivoid-core/session"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// Client is the HiVoid QUIC client.
type Client struct {
	serverAddr string
	tlsCfg     *quic.Transport
	mode       intelligence.Mode
	insecure   bool
	logger     *zap.Logger
	manager    *session.Manager
	control    func(fd int)
}

// ClientConfig holds client startup options.
type ClientConfig struct {
	// ServerAddr is "host:port" of the HiVoid server.
	ServerAddr string
	// Mode is the default operating mode.
	Mode intelligence.Mode
	// ObfsName is the requested obfuscation type name.
	ObfsName string
	// ObfsConfig is the obfuscation config.
	ObfsConfig obfuscation.Config
	// Insecure disables TLS certificate verification (testing only).
	Insecure bool
	// Logger is an optional structured logger.
	Logger *zap.Logger
	// UUID is the 16-byte client identity sent in ClientHello.
	// Obtain it from config.Config.UUIDBytes(). Leave zero for anonymous.
	UUID [16]byte
	// SocketControl is an optional callback called after each socket is created.
	// Essential for Android VpnService.protect().
	SocketControl func(fd int)
}

// NewClient creates a new HiVoid client.
func NewClient(cfg ClientConfig) *Client {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	mgr := session.NewManager(true, cfg.Mode, logger)
	if cfg.ObfsName != "" {
		mgr.SetObfuscation(cfg.ObfsConfig)
		mgr.SetClientParams(cfg.Mode, cfg.ObfsName)
	}
	if cfg.UUID != ([16]byte{}) {
		mgr.SetClientUUID(cfg.UUID)
	}
	return &Client{
		serverAddr: cfg.ServerAddr,
		mode:       cfg.Mode,
		insecure:   cfg.Insecure,
		logger:     logger,
		manager:    mgr,
		control:    cfg.SocketControl,
	}
}

// Connect establishes a QUIC connection to the server, performs the TLS
// handshake, and then executes the HiVoid hybrid key exchange.
// Returns the active Session ready for data transfer.
func (c *Client) Connect(ctx context.Context) (*session.Session, error) {
	addr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve server addr: %w", err)
	}

	// Bind to an ephemeral local UDP port with socket protection support
	var udpConn *net.UDPConn
	if c.control != nil {
		lc := net.ListenConfig{
			Control: func(network, address string, raw syscall.RawConn) error {
				return raw.Control(func(fd uintptr) {
					c.control(int(fd))
				})
			},
		}
		pc, err := lc.ListenPacket(ctx, "udp", ":0")
		if err != nil {
			return nil, fmt.Errorf("listen packet: %w", err)
		}
		udpConn = pc.(*net.UDPConn)
	} else {
		var err error
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, fmt.Errorf("listen udp: %w", err)
		}
	}

	// Increase OS UDP buffers for high-throughput QUIC
	_ = udpConn.SetReadBuffer(4 * 1024 * 1024)
	_ = udpConn.SetWriteBuffer(4 * 1024 * 1024)

	transport := &quic.Transport{
		Conn: udpConn,
	}

	// Extract host for SNI
	host, _, _ := net.SplitHostPort(c.serverAddr)
	tlsCfg := ClientTLSConfig(host, c.insecure)

	c.logger.Info("connecting",
		zap.String("server", c.serverAddr),
		zap.String("mode", c.mode.String()),
	)

	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	conn, err := transport.Dial(connectCtx, addr, tlsCfg, QUICConfig())
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	c.logger.Info("quic connected, starting hivoid handshake")

	return c.manager.Dial(ctx, conn)
}

// Manager returns the session manager (for managing multiple connections).
func (c *Client) Manager() *session.Manager {
	return c.manager
}

// Close shuts down all client sessions.
func (c *Client) Close() {
	c.manager.CloseAll()
}
