package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/hivoid-org/hivoid-core/config"
	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/transport"
	"github.com/hivoid-org/hivoid-core/utils"
)

// runPing handles `hivoid-client ping --config <path>`.
// Connects to the server multiple times and measures latency.
func runPing(args []string) {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to JSON config file")
	uriStr := fs.String("uri", "", "HiVoid URI string")
	count := fs.Int("c", 4, "Number of ping attempts")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: hivoid-client ping --config <file.json> [-c 4]")
		fmt.Fprintln(os.Stderr, "       hivoid-client ping --uri <hivoid://...> [-c 4]")
		fs.PrintDefaults()
	}
	fs.Parse(args) //nolint:errcheck

	// Load config
	var cfg *config.Config
	var err error
	if *uriStr != "" {
		cfg, err = config.ParseURI(*uriStr)
	} else if *configPath != "" {
		cfg, err = config.LoadJSON(*configPath)
	} else {
		fmt.Fprintln(os.Stderr, "error: --config or --uri is required")
		fs.Usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger, _ := utils.NewLogger(false)
	mode := intelligence.ModeFromString(cfg.Mode)

	uuidBytes, err := cfg.UUIDBytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid uuid: %v\n", err)
		os.Exit(1)
	}

	addr := cfg.ServerAddr()
	fmt.Printf("\nPING %s (HiVoid over QUIC)\n\n", addr)

	var results []time.Duration
	var failures int

	for i := 1; i <= *count; i++ {
		hvClient := transport.NewClient(transport.ClientConfig{
			ServerAddr: addr,
			Mode:       mode,
			Insecure:   cfg.Insecure,
			Logger:     logger,
			UUID:       uuidBytes,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		start := time.Now()
		sess, err := hvClient.Connect(ctx)
		elapsed := time.Since(start)
		cancel()

		if err != nil {
			fmt.Printf("  #%d  FAIL  (%v)\n", i, err)
			failures++
			hvClient.Close()
			continue
		}

		results = append(results, elapsed)
		fmt.Printf("  #%d  %s  (QUIC + handshake)\n", i, formatDuration(elapsed))

		sess.Close()
		hvClient.Close()

		// Small pause between attempts
		if i < *count {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Print statistics
	fmt.Printf("\n--- %s ping statistics ---\n", addr)
	if len(results) == 0 {
		fmt.Printf("%d attempts, %d failed, 100%% loss\n", *count, failures)
		os.Exit(1)
	}

	minD, maxD, avgD, jitter := calcStats(results)
	loss := float64(failures) / float64(*count) * 100

	fmt.Printf("%d attempts, %d ok, %d failed (%.0f%% loss)\n",
		*count, len(results), failures, loss)
	fmt.Printf("min=%s  avg=%s  max=%s  jitter=%s\n\n",
		formatDuration(minD),
		formatDuration(avgD),
		formatDuration(maxD),
		formatDuration(jitter),
	)
}

// calcStats computes min, max, average, and jitter from a slice of durations.
func calcStats(results []time.Duration) (min, max, avg, jitter time.Duration) {
	if len(results) == 0 {
		return
	}

	min = results[0]
	max = results[0]
	var total time.Duration

	for _, d := range results {
		total += d
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	avg = total / time.Duration(len(results))

	// Jitter = mean absolute deviation from the average
	if len(results) > 1 {
		var devTotal float64
		avgF := float64(avg)
		for _, d := range results {
			devTotal += math.Abs(float64(d) - avgF)
		}
		jitter = time.Duration(devTotal / float64(len(results)))
	}
	return
}

// formatDuration formats a duration as a human-readable string.
func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%.0fus", float64(d.Microseconds()))
	}
	if d < time.Second {
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}
