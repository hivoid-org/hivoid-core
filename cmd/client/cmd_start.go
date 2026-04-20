package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/hivoid-org/hivoid-core/client"
	"github.com/hivoid-org/hivoid-core/config"
	"github.com/hivoid-org/hivoid-core/geodata"
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
		ServerAddrs: cfg.ServerAddrs(),
		Mode:        mode,
		ObfsName:    cfg.Obfs,
		ObfsConfig:  session.ObfsConfigForName(cfg.Obfs),
		Insecure:    cfg.Insecure,
		Logger:      logger,
		UUID:        uuidBytes,
	})
	defer hvClient.Close()

	sigs := []os.Signal{os.Interrupt}
	if runtime.GOOS != "windows" {
		sigs = append(sigs, syscall.SIGTERM)
	}
	ctx, stop := signal.NotifyContext(context.Background(), sigs...)
	defer stop()

	logger.Info("initializing session pool", zap.Strings("servers", cfg.ServerAddrs()), zap.Int("pool_size", cfg.PoolSize))
	pool, err := client.NewSessionPool(ctx, cfg, hvClient, logger)
	if err != nil {
		logger.Fatal("failed to initialize session pool", zap.Error(err))
	}
	defer pool.Close()

	bypassDomains := cfg.EffectiveBypassDomains()
	parsedBypassIPs := client.ParseBypassIPStrings(cfg.EffectiveBypassIPs(), logger)
	tags := cfg.EffectiveDirectRouteTags()
	if cfg.GeoIPPath != "" || cfg.GeoSitePath != "" {
		if len(tags) > 0 {
			beforeDomains := len(bypassDomains)
			beforeIPs := len(parsedBypassIPs)
			_ = geodata.LoadGeoData(cfg.GeoIPPath, cfg.GeoSitePath, tags, &bypassDomains, &parsedBypassIPs)
			if len(bypassDomains) > beforeDomains || len(parsedBypassIPs) > beforeIPs {
				logger.Info("geodata loaded successfully", zap.Int("domains", len(bypassDomains)), zap.Int("ips", len(parsedBypassIPs)))
			}
		}
	}

	dialTunnel := func(dialCtx context.Context, target string, udp bool) (net.Conn, error) {
		return pool.DialTunnel(dialCtx, target, udp)
	}

	// DNS proxy
	if cfg.DNSPort > 0 {
		dnsCfg := client.DNSProxyConfig{
			ListenAddr:    fmt.Sprintf("127.0.0.1:%d", cfg.DNSPort),
			UpstreamDNS:   cfg.DNSUpstream,
			Logger:        logger,
			BypassDomains: bypassDomains,
			BypassIPs:     parsedBypassIPs,
			DirectDNS:     cfg.DirectDNSServers,
		}
		dnsProxy := client.NewDNSProxy(dnsCfg, func(ctx context.Context, target string) (net.Conn, error) {
			return dialTunnel(ctx, target, false) // DNS upstream over TCP tunnel
		})
		go func() { dnsProxy.ListenAndServe(ctx) }() //nolint:errcheck
	}

	// SOCKS5 / HTTP proxy
	var proxyAddr string
	if cfg.SocksPort > 0 {
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", cfg.SocksPort)

		proxyCfg := client.ProxyConfig{
			ListenAddr:    proxyAddr,
			EnableSOCKS5:  true,
			EnableHTTP:    true,
			Logger:        logger,
			BypassDomains: bypassDomains,
			BypassIPs:     parsedBypassIPs,
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
	smartDNS := len(bypassDomains) > 0 || len(parsedBypassIPs) > 0
	printStartBox(cfg, proxyAddr, smartDNS)

	<-ctx.Done()
	fmt.Println("\nHiVoid stopped.")
}

// printStartBox prints the startup information box.
func printStartBox(cfg *config.Config, proxyAddr string, smartDNS bool) {
	dns := "disabled"
	if cfg.DNSPort > 0 {
		dns = fmt.Sprintf("127.0.0.1:%d → tunnel %s", cfg.DNSPort, cfg.DNSUpstream)
		if smartDNS {
			dns += " (+ direct DNS for bypass)"
		}
	}
	proxy := proxyAddr
	if proxy == "" {
		proxy = "disabled"
	}

	fmt.Printf("\n======================================================\n")
	fmt.Printf("  HiVoid — %s\n", cfg.Name)
	fmt.Printf("======================================================\n")
	fmt.Printf("  Server:   %s\n", cfg.ServerAddr())
	fmt.Printf("  SOCKS5:   %s\n", proxy)
	fmt.Printf("  DNS:      %s\n", dns)
	fmt.Printf("  Mode:     %s\n", upper(cfg.Mode))
	fmt.Printf("  Obfs:     %s\n", upper(cfg.Obfs))
	fmt.Printf("======================================================\n")
	fmt.Printf("  Press Ctrl+C or run 'hivoid-client stop'.\n")
	fmt.Printf("======================================================\n\n")
}

// connectRetry tries up to 3 times with exponential back-off.
func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
