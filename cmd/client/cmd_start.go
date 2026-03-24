package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hivoid-org/hivoid-core/client"
	"github.com/hivoid-org/hivoid-core/config"
	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/session"
	"github.com/hivoid-org/hivoid-core/transport"
	"github.com/hivoid-org/hivoid-core/utils"
	"go.uber.org/zap"
)

// runStart handles `hivoid-client start --config <path>`.
func runStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to JSON config file (required)")
	uriStr := fs.String("uri", "", "HiVoid URI string (hivoid://uuid@host:port?params#name)")
	debug := fs.Bool("debug", false, "Enable debug logging")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: hivoid-client start --config <file.json> [--debug]")
		fmt.Fprintln(os.Stderr, "       hivoid-client start --uri <hivoid://...> [--debug]")
		fs.PrintDefaults()
	}
	fs.Parse(args) //nolint:errcheck

	// Load config from --config or --uri
	var cfg *config.Config
	var err error
	if *uriStr != "" {
		cfg, err = config.ParseURI(*uriStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid URI: %v\n", err)
			os.Exit(1)
		}
	} else if *configPath != "" {
		cfg, err = config.LoadJSON(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "error: --config or --uri is required")
		fs.Usage()
		os.Exit(1)
	}

	logger, err := utils.NewLogger(*debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck
	utils.SetGlobalLogger(logger)

	// Connect to server
	mode := intelligence.ModeFromString(cfg.Mode)
	uuidBytes, err := cfg.UUIDBytes()
	if err != nil {
		logger.Fatal("invalid uuid in config", zap.Error(err))
	}

	hvClient := transport.NewClient(transport.ClientConfig{
		ServerAddr: cfg.ServerAddr(),
		Mode:       mode,
		ObfsName:   cfg.Obfs,
		ObfsConfig: session.ObfsConfigForName(cfg.Obfs),
		Insecure:   cfg.Insecure,
		Logger:     logger,
		UUID:       uuidBytes,
	})
	defer hvClient.Close()

	sigs := []os.Signal{os.Interrupt}
	if runtime.GOOS != "windows" {
		sigs = append(sigs, syscall.SIGTERM)
	}
	ctx, stop := signal.NotifyContext(context.Background(), sigs...)
	defer stop()

	logger.Info("connecting", zap.String("server", cfg.ServerAddr()), zap.String("name", cfg.Name))

	sess, err := connectRetry(ctx, hvClient, logger)
	if err != nil {
		logger.Fatal("connect failed", zap.Error(err))
	}
	logger.Info("session established", zap.String("session", sess.ID().String()))

	var sessMu sync.RWMutex
	var reconnectMu sync.Mutex
	currentSess := sess
	setSession := func(next *session.Session) {
		sessMu.Lock()
		old := currentSess
		currentSess = next
		sessMu.Unlock()
		if old != nil && old != next {
			_ = old.Close()
		}
	}
	getSession := func() *session.Session {
		sessMu.RLock()
		defer sessMu.RUnlock()
		return currentSess
	}
	reconnect := func(dialCtx context.Context) (*session.Session, error) {
		reconnectMu.Lock()
		defer reconnectMu.Unlock()

		if s := getSession(); s != nil && s.State() == session.StateActive {
			return s, nil
		}

		next, err := connectRetry(dialCtx, hvClient, logger)
		if err != nil {
			return nil, err
		}
		setSession(next)
		logger.Info("session re-established", zap.String("session", next.ID().String()))
		return next, nil
	}
	dialTunnel := func(dialCtx context.Context, target string) (net.Conn, error) {
		s := getSession()
		if s == nil || s.State() != session.StateActive {
			var err error
			s, err = reconnect(dialCtx)
			if err != nil {
				return nil, fmt.Errorf("reconnect: %w", err)
			}
		}

		conn, err := s.DialTunnel(dialCtx, target)
		if err == nil {
			return conn, nil
		}
		if !shouldRetryWithReconnect(err) {
			return nil, err
		}

		logger.Warn("dial failed, reconnecting session", zap.String("target", target), zap.Error(err))
		s, rerr := reconnect(dialCtx)
		if rerr != nil {
			return nil, fmt.Errorf("dial failed: %v; reconnect failed: %w", err, rerr)
		}
		return s.DialTunnel(dialCtx, target)
	}

	// DNS proxy
	if cfg.DNSPort > 0 {
		dnsCfg := client.DNSProxyConfig{
			ListenAddr:  fmt.Sprintf("127.0.0.1:%d", cfg.DNSPort),
			UpstreamDNS: cfg.DNSUpstream,
			Logger:      logger,
		}
		dnsProxy := client.NewDNSProxy(dnsCfg, dialTunnel)
		go func() { dnsProxy.ListenAndServe(ctx) }() //nolint:errcheck
	}

	// SOCKS5 / HTTP proxy
	var proxyAddr string
	if cfg.SocksPort > 0 {
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.SocksPort)
		proxyCfg := client.ProxyConfig{
			ListenAddr:   proxyAddr,
			EnableSOCKS5: true,
			EnableHTTP:   true,
			Logger:       logger,
		}
		proxy := client.NewProxyServer(proxyCfg, dialTunnel)
		defer proxy.Close()                       //nolint:errcheck
		go func() { proxy.ListenAndServe(ctx) }() //nolint:errcheck
	}

	// Write PID file
	if err := writePID(); err != nil {
		logger.Warn("write pid file", zap.Error(err))
	}
	defer removePID() //nolint:errcheck

	// Print startup summary
	printStartBox(cfg, proxyAddr)

	<-ctx.Done()
	fmt.Println("\nHiVoid stopped.")
}

// printStartBox prints the startup information box.
func printStartBox(cfg *config.Config, proxyAddr string) {
	dns := "disabled"
	if cfg.DNSPort > 0 {
		dns = fmt.Sprintf("127.0.0.1:%d → %s", cfg.DNSPort, cfg.DNSUpstream)
	}
	proxy := proxyAddr
	if proxy == "" {
		proxy = "disabled"
	}

	fmt.Printf("\n┌─────────────────────────────────────────────────┐\n")
	fmt.Printf("│  HiVoid  %-38s│\n", "— "+cfg.Name)
	fmt.Printf("├─────────────────────────────────────────────────┤\n")
	fmt.Printf("│  Server:   %-37s│\n", cfg.ServerAddr())
	fmt.Printf("│  SOCKS5:   %-37s│\n", proxy)
	fmt.Printf("│  DNS:      %-37s│\n", dns)
	fmt.Printf("│  Mode:     %-37s│\n", upper(cfg.Mode))
	fmt.Printf("│  Obfs:     %-37s│\n", upper(cfg.Obfs))
	fmt.Printf("├─────────────────────────────────────────────────┤\n")
	fmt.Printf("│  Press Ctrl+C or run 'hivoid-client stop'.      │\n")
	fmt.Printf("└─────────────────────────────────────────────────┘\n\n")
}

// connectRetry tries up to 3 times with exponential back-off.
func connectRetry(ctx context.Context, c *transport.Client, log *zap.Logger) (*session.Session, error) {
	var last error
	for i := 1; i <= 3; i++ {
		s, err := c.Connect(ctx)
		if err == nil {
			return s, nil
		}
		last = err
		if i < 3 {
			wait := time.Duration(i) * time.Second
			log.Warn("retrying", zap.Int("attempt", i), zap.Duration("wait", wait), zap.Error(err))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
	}
	return nil, fmt.Errorf("after 3 attempts: %w", last)
}

// upper converts to uppercase using ASCII only.
func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func shouldRetryWithReconnect(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "proxy connect failed") {
		return false
	}
	for _, key := range []string{
		"session not active",
		"open tunnel stream",
		"connection closed",
		"application error",
		"broken pipe",
		"eof",
	} {
		if strings.Contains(msg, key) {
			return true
		}
	}
	return false
}
