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
	serverAddrs []string
	engine      *intelligence.Engine
	tlsCfg      *quic.Transport
	mode        intelligence.Mode
	insecure    bool
	logger      *zap.Logger
	manager     *session.Manager
	control     func(fd int)
}

// ClientConfig holds client startup options.
type ClientConfig struct {
	// ServerAddrs is a list of "host:port" for HiVoid servers.
	// The client will automatically pick the best one based on probing.
	ServerAddrs []string
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
	// Persistence enables saving of engine metrics to disk.
	Persistence bool
	// StateFile is the path where engine metrics are stored.
	StateFile string
}

// NewClient creates a new HiVoid client.
func NewClient(cfg ClientConfig) *Client {
	logger := cfg.Logger
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	
	engine := intelligence.NewEngine(cfg.Mode)
	if cfg.Persistence && cfg.StateFile != "" {
		engine.SetStatePath(cfg.StateFile)
	}
	engine.SetProbeTargets(cfg.ServerAddrs)
	engine.Start()

	mgr := session.NewManager(true, cfg.Mode, logger)
	if cfg.ObfsName != "" {
		mgr.SetObfuscation(cfg.ObfsConfig)
		mgr.SetClientParams(cfg.Mode, cfg.ObfsName)
	}
	if cfg.UUID != ([16]byte{}) {
		mgr.SetClientUUID(cfg.UUID)
	}

	return &Client{
		serverAddrs: cfg.ServerAddrs,
		engine:      engine,
		mode:        cfg.Mode,
		insecure:    cfg.Insecure,
		logger:      logger,
		manager:     mgr,
		control:     cfg.SocketControl,
	}
}

// Connect establishes a QUIC connection to the best available server.
func (c *Client) Connect(ctx context.Context) (*session.Session, error) {
	serverAddr := c.pickBestServer()
	
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
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
	host, _, _ := net.SplitHostPort(serverAddr)
	tlsCfg := ClientTLSConfig(host, c.insecure)
 
	c.logger.Info("connecting",
		zap.String("server", serverAddr),
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

// pickBestServer selects the server with the best probe results.
func (c *Client) pickBestServer() string {
	results := c.engine.ProbeResults()
	if len(results) == 0 {
		if len(c.serverAddrs) > 0 {
			return c.serverAddrs[0]
		}
		return ""
	}

	best := results[0].Target
	minRTT := results[0].RTT
	
	found := false
	for _, r := range results {
		if r.Success {
			if !found || r.RTT < minRTT {
				minRTT = r.RTT
				best = r.Target
				found = true
			}
		}
	}

	if !found && len(c.serverAddrs) > 0 {
		return c.serverAddrs[0]
	}
	return best
}

// Manager returns the session manager (for managing multiple connections).
func (c *Client) Manager() *session.Manager {
	return c.manager
}

// Engine returns the intelligence engine.
func (c *Client) Engine() *intelligence.Engine {
	return c.engine
}

// Close shuts down all client sessions and the engine.
func (c *Client) Close() {
	c.engine.Stop()
	c.manager.CloseAll()
}
