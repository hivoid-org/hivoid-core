package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hivoid-org/hivoid-core/config"
	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/server"
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
	fwdCfg := server.DefaultForwarderConfig()
	fwdCfg.Logger = logger
	fwdCfg.MaxConnections = cfg.MaxConns
	if len(cfg.AllowedHosts) > 0 {
		fwdCfg.AllowedHosts = cfg.AllowedHosts
	}
	if len(cfg.BlockedHosts) > 0 {
		fwdCfg.BlockedHosts = cfg.BlockedHosts
	}
	forwarder := server.NewForwarder(fwdCfg)

	// Parse allowed UUIDs
	var allowedUUIDs [][16]byte
	for _, raw := range cfg.AllowedUUIDs {
		tmpCfg := &config.Config{UUID: raw, Server: "x", Port: 1}
		b, err := tmpCfg.UUIDBytes()
		if err != nil {
			logger.Warn("skipping malformed uuid", zap.String("uuid", raw), zap.Error(err))
			continue
		}
		allowedUUIDs = append(allowedUUIDs, b)
	}

	logger.Info("hivoid server starting",
		zap.String("listen", listenAddr),
		zap.String("mode", mode.String()),
		zap.Int("max_conns", cfg.MaxConns),
		zap.Int("allowed_uuids", len(allowedUUIDs)),
	)

	srv := transport.NewServer(transport.ServerConfig{
		ListenAddr:   listenAddr,
		CertFile:     cfg.Cert,
		KeyFile:      cfg.Key,
		Mode:         mode,
		Logger:       logger,
		Handler:      forwarder.Handler(),
		AllowedUUIDs: allowedUUIDs,
	})
	defer srv.Close() //nolint:errcheck

	// Write PID file
	if err := writePID(); err != nil {
		logger.Warn("write pid file", zap.Error(err))
	}
	defer removePID() //nolint:errcheck

	// Print startup box
	printServerBox(cfg, listenAddr, len(allowedUUIDs))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.ListenAndServe(ctx); err != nil {
		logger.Error("server error", zap.Error(err))
		os.Exit(1)
	}

	forwarder.Wait()
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

// splitCSV splits a comma-separated string into a trimmed slice.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
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
