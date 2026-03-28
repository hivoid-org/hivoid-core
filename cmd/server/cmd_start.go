package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
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

// runStart handles `hivoid-server start --config <path>`.
func runStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to server JSON config file (required)")
	debug := fs.Bool("debug", false, "Enable debug logging")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: hivoid-server start --config <server.json> [--debug]")
		fs.PrintDefaults()
	}
	fs.Parse(args) //nolint:errcheck

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config is required")
		fs.Usage()
		os.Exit(1)
	}

	// Load config
	cfg, err := config.LoadServerJSON(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	if *debug {
		cfg.Debug = true
	}

	logger, err := utils.NewLogger(cfg.Debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger init: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck
	utils.SetGlobalLogger(logger)

	// Validate cert/key files exist
	for _, f := range []string{cfg.Cert, cfg.Key} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			logger.Fatal("file not found", zap.String("path", f))
		}
	}

	mode := intelligence.ModeFromString(cfg.Mode)
	listenAddr := cfg.Listen()

	// Build the forwarder
	usagePath := *configPath + ".usage.json"
	userControls := server.NewUserControlManager(logger, usagePath)
	fwdCfg := server.DefaultForwarderConfig()
	fwdCfg.Logger = logger
	fwdCfg.UserControls = userControls
	forwarder := server.NewForwarder(fwdCfg)

	srv := transport.NewServer(transport.ServerConfig{
		ListenAddr:   listenAddr,
		CertFile:     cfg.Cert,
		KeyFile:      cfg.Key,
		Mode:         mode,
		Logger:       logger,
		Handler:      forwarder.Handler(),
		AllowedUUIDs: nil,
		AntiProbe:    cfg.AntiProbe,
		FallbackAddr: cfg.FallbackAddr,
	})
	defer srv.Close() //nolint:errcheck

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
		allowedUUIDs, userPolicies := buildRuntimePolicies(next, userControls, logger)
		srv.Manager().SetMode(intelligence.ModeFromString(next.Mode))
		srv.Manager().SetObfuscation(session.ObfsConfigForName(next.Obfs))
		srv.Manager().SetAllowedUUIDs(allowedUUIDs)
		srv.Manager().SetUserPolicies(userPolicies)
		srv.Manager().RefreshActiveSessionPolicies()
		userControls.ApplyPolicies(userPolicies)

		forwarder.UpdateRuntime(server.ForwarderConfig{
			DialTimeout:         10 * time.Second,
			MaxConnections:      next.MaxConns,
			AllowedHosts:        next.AllowedHosts,
			BlockedHosts:        next.BlockedHosts,
			Logger:              logger,
			Users:               userPolicies,
			ConnectionTracking:  next.ConnectionTracking,
			UserControls:        userControls,
			DisconnectExpired:   next.DisconnectExpired,
		})
		logger.Info("runtime config applied",
			zap.String("mode", intelligence.ModeFromString(next.Mode).String()),
			zap.Int("users", len(userPolicies)),
			zap.Int("allowed_uuids", len(allowedUUIDs)),
			zap.Int("max_conns", next.MaxConns),
		)
		return nil
	}
	if err := applyRuntime(cfg); err != nil {
		logger.Fatal("apply runtime config failed", zap.Error(err))
	}

	logger.Info("hivoid server starting",
		zap.String("listen", listenAddr),
		zap.String("mode", mode.String()),
		zap.Int("max_conns", cfg.MaxConns),
	)

	// Write PID file
	if err := writePID(); err != nil {
		logger.Warn("write pid file", zap.Error(err))
	}
	defer removePID() //nolint:errcheck

	// Print startup box
	allowedUUIDs, _ := buildRuntimePolicies(cfg, userControls, logger)
	printServerBox(cfg, listenAddr, len(allowedUUIDs))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	flushStop := make(chan struct{})
	userControls.StartPeriodicFlush(flushStop, 10*time.Second)
	defer func() {
		close(flushStop)
		if err := userControls.Flush(); err != nil {
			logger.Warn("final usage flush failed", zap.Error(err))
		}
	}()
	if cfg.HotReload {
		cfgMgr := server.NewConfigManager(*configPath, time.Second, logger)
		go func() {
			if err := cfgMgr.Start(ctx, applyRuntime); err != nil && ctx.Err() == nil {
				logger.Error("config manager stopped", zap.Error(err))
			}
		}()
	}
	
	// Start background quota enforcement
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
	if err := userControls.Flush(); err != nil {
		logger.Warn("usage flush failed", zap.Error(err))
	}
	fmt.Println("\nHiVoid server stopped.")
}

// printServerBox prints the startup information box.
func printServerBox(cfg *config.ServerConfig, listenAddr string, numUUIDs int) {
	uuids := "all (no allowlist)"
	if numUUIDs > 0 {
		uuids = fmt.Sprintf("%d configured", numUUIDs)
	}

	fmt.Printf("\n┌─────────────────────────────────────────────────┐\n")
	fmt.Printf("│  HiVoid Server                                  │\n")
	fmt.Printf("├─────────────────────────────────────────────────┤\n")
	fmt.Printf("│  Listen:   %-37s│\n", listenAddr)
	fmt.Printf("│  Mode:     %-37s│\n", upper(cfg.Mode))
	fmt.Printf("│  Obfs:     %-37s│\n", upper(cfg.Obfs))
	fmt.Printf("│  UUIDs:    %-37s│\n", uuids)
	fmt.Printf("├─────────────────────────────────────────────────┤\n")
	fmt.Printf("│  Press Ctrl+C or run 'hivoid-server stop'.      │\n")
	fmt.Printf("└─────────────────────────────────────────────────┘\n\n")
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

func buildRuntimePolicies(cfg *config.ServerConfig, userControls *server.UserControlManager, logger *zap.Logger) ([][16]byte, map[[16]byte]session.UserPolicy) {
	allowedUUIDs := make([][16]byte, 0, len(cfg.AllowedUUIDs))
	userPolicies := make(map[[16]byte]session.UserPolicy, len(cfg.Users))
	for _, u := range cfg.Users {
		tmpCfg := &config.Config{UUID: u.UUID, Server: "x", Port: 1}
		id, err := tmpCfg.UUIDBytes()
		if err != nil {
			logger.Warn("skipping malformed user uuid", zap.String("uuid", u.UUID), zap.Error(err))
			continue
		}

		// Use the higher of config value or real-time tracked usage
		bytesIn, bytesOut := u.BytesIn, u.BytesOut
		if userControls != nil {
			liveIn, liveOut := userControls.UserUsage(id)
			if liveIn > bytesIn {
				bytesIn = liveIn
			}
			if liveOut > bytesOut {
				bytesOut = liveOut
			}
		}

		userPolicies[id] = session.UserPolicy{
			UUID:           id,
			Email:          u.Email,
			Mode:           intelligence.ModeFromString(u.Mode),
			ObfsConfig:     session.ObfsConfigForName(u.Obfs),
			MaxConnections: u.MaxConnections,
			MaxIPs:         u.MaxIPs,
			BindIP:         u.BindIP,
			BandwidthLimit: u.BandwidthLimit,
			ExpireAtUnix:   parseExpireAt(u.ExpireAt),
			BytesIn:        bytesIn,
			BytesOut:       bytesOut,
			Enabled:        u.Enabled,
		}
		if u.Enabled {
			allowedUUIDs = append(allowedUUIDs, id)
		}
	}
	if len(cfg.Users) == 0 {
		for _, raw := range cfg.AllowedUUIDs {
			tmpCfg := &config.Config{UUID: raw, Server: "x", Port: 1}
			b, err := tmpCfg.UUIDBytes()
			if err != nil {
				logger.Warn("skipping malformed uuid", zap.String("uuid", raw), zap.Error(err))
				continue
			}
			allowedUUIDs = append(allowedUUIDs, b)
		}
	}
	return allowedUUIDs, userPolicies
}

func parseExpireAt(raw string) int64 {
	if raw == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return 0
	}
	return t.Unix()
}
