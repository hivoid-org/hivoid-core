package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hivoid-org/hivoid-core/config"
	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/server"
	"github.com/hivoid-org/hivoid-core/session"
	"github.com/hivoid-org/hivoid-core/transport"
	"github.com/hivoid-org/hivoid-core/utils"
	"go.uber.org/zap"
)

// runHub handles `hivoid-server hub --config <path>`.
// It runs in stateless mode, relying entirely on the Subscription Hub.
func runHub(args []string) {
	fs := flag.NewFlagSet("hub", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to hub-only JSON config file (required)")
	debug := fs.Bool("debug", false, "Enable debug logging")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: hivoid-server hub --config <hub.json> [--debug]")
		fs.PrintDefaults()
	}
	fs.Parse(args) //nolint:errcheck

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		fs.Usage()
		os.Exit(1)
	}

	// Load Hub-Only config
	data, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read config: %v\n", err)
		os.Exit(1)
	}

	var hCfg config.HubOnlyConfig
	if err := json.Unmarshal(data, &hCfg); err != nil {
		fmt.Fprintf(os.Stderr, "invalid hub config format: %v\n", err)
		os.Exit(1)
	}

	// Validate minimal requirements
	if hCfg.Endpoint == "" || hCfg.NodeToken == "" {
		fmt.Fprintln(os.Stderr, "error: endpoint and node_token are required in hub config")
		os.Exit(1)
	}
	if hCfg.Port == 0 {
		hCfg.Port = 4433
	}

	logger, _ := utils.NewLogger(*debug)
	defer logger.Sync() //nolint:errcheck

	logger.Info("starting in HUB SLAVE MODE (stateless)",
		zap.String("hub_endpoint", hCfg.Endpoint),
		zap.Int("listen_port", hCfg.Port),
	)

	// Build the forwarder (no users initially)
	usagePath := *configPath + ".usage.json"
	userControls := server.NewUserControlManager(logger, usagePath)
	fwdCfg := server.DefaultForwarderConfig()
	fwdCfg.Logger = logger
	fwdCfg.UserControls = userControls
	forwarder := server.NewForwarder(fwdCfg)

	listenAddr := fmt.Sprintf("0.0.0.0:%d", hCfg.Port)
	srv := transport.NewServer(transport.ServerConfig{
		ListenAddr: listenAddr,
		CertFile:   hCfg.Cert,
		KeyFile:    hCfg.Key,
		Mode:       intelligence.ModeAdaptive, // Slave mode defaults to Adaptive
		Logger:     logger,
		Handler:    forwarder.Handler(),
		AntiProbe:  true, // Enabled by default in hub mode
	})
	defer srv.Close() //nolint:errcheck
	runtimeCfg := &config.ServerConfig{
		Server:             "0.0.0.0",
		Port:               hCfg.Port,
		Cert:               hCfg.Cert,
		Key:                hCfg.Key,
		Mode:               config.DefaultMode,
		Obfs:               config.DefaultObfs,
		MaxConns:           0,
		AntiProbe:          true,
		ConnectionTracking: false,
		DisconnectExpired:  false,
	}
	var runtimeMu sync.RWMutex
	applyForwarderRuntime := func(userPolicies map[[16]byte]session.UserPolicy) {
		runtimeMu.RLock()
		snap := *runtimeCfg
		runtimeMu.RUnlock()
		forwarder.UpdateRuntime(server.ForwarderConfig{
			DialTimeout:        10 * time.Second,
			MaxConnections:     snap.MaxConns,
			AllowedHosts:       snap.AllowedHosts,
			BlockedHosts:       snap.BlockedHosts,
			Logger:             logger,
			Users:              userPolicies,
			ConnectionTracking: snap.ConnectionTracking,
			UserControls:       userControls,
			DisconnectExpired:  snap.DisconnectExpired,
			GeoIPPath:          snap.GeoIPPath,
			GeoSitePath:        snap.GeoSitePath,
			BlockedTags:        snap.BlockedTags,
		})
	}
	applyRuntime := func(next *config.ServerConfig) error {
		if err := srv.ReloadConfig(transport.ServerConfig{
			ListenAddr:   next.Listen(),
			CertFile:     next.Cert,
			KeyFile:      next.Key,
			AntiProbe:    next.AntiProbe,
			FallbackAddr: next.FallbackAddr,
		}); err != nil {
			return err
		}
		srv.Manager().SetMode(intelligence.ModeFromString(next.Mode))
		srv.Manager().SetObfuscation(session.ObfsConfigForName(next.Obfs))
		userPolicies := srv.Manager().GetPoliciesSnapshot()
		srv.Manager().SetAllowedUUIDs(enabledUUIDsFromPolicies(userPolicies))

		runtimeMu.Lock()
		*runtimeCfg = *next
		runtimeMu.Unlock()
		applyForwarderRuntime(userPolicies)
		return nil
	}
	if err := applyRuntime(runtimeCfg); err != nil {
		logger.Error("initial hub runtime apply failed", zap.Error(err))
		os.Exit(1)
	}

	// Map HubOnlyConfig to standard HubConfig
	hubClientCfg := config.HubConfig{
		Endpoint:       hCfg.Endpoint,
		NodeToken:      hCfg.NodeToken,
		SyncIntervalMs: hCfg.SyncIntervalMs,
		Insecure:       hCfg.Insecure,
	}

	// Start Hub Client
	hubClient := server.NewHubClient(
		hubClientCfg,
		srv.Manager(),
		userControls,
		logger,
		applyRuntime,
		applyForwarderRuntime,
		runtimeCfg,
	)
	hubClient.Start()
	defer hubClient.Stop()

	// Print startup box
	printHubBox(hCfg, listenAddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Periodic usage flush
	flushStop := make(chan struct{})
	userControls.StartPeriodicFlush(flushStop, 10*time.Second)
	defer func() {
		close(flushStop)
		_ = userControls.Flush()
	}()

	// Background quota enforcement
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				srv.Manager().EnforceQuotas()
			}
		}
	}()

	if err := srv.ListenAndServe(ctx); err != nil {
		logger.Error("server error", zap.Error(err))
		os.Exit(1)
	}

	forwarder.Wait()
	_ = userControls.Flush()
	fmt.Println("\nHiVoid Hub-Slave stopped.")
}

func printHubBox(cfg config.HubOnlyConfig, listenAddr string) {
	fmt.Printf("\n┌─────────────────────────────────────────────────┐\n")
	fmt.Printf("│  HiVoid Server - HUB SLAVE MODE                 │\n")
	fmt.Printf("├─────────────────────────────────────────────────┤\n")
	fmt.Printf("│  Listen:   %-37s│\n", listenAddr)
	fmt.Printf("│  Hub:      %-37s│\n", cfg.Endpoint)
	fmt.Printf("│  Status:   Waiting for SYNC from Master Hub...  │\n")
	fmt.Printf("├─────────────────────────────────────────────────┤\n")
	fmt.Printf("│  State:    Stateless                            │\n")
	fmt.Printf("└─────────────────────────────────────────────────┘\n\n")
}
