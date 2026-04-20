// Package intelligence — active network probing.
package intelligence

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ProbeResult represents the outcome of a single active probe.
type ProbeResult struct {
	Target  string
	RTT     time.Duration
	Success bool
	Error   error
}

// Prober performs active health checks on HiVoid servers.
type Prober struct {
	timeout time.Duration
}

// NewProber creates a Prober with the given timeout.
func NewProber(timeout time.Duration) *Prober {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Prober{timeout: timeout}
}

// Probe checks the health of a target HiVoid server using a lightweight QUIC handshake.
// It doesn't perform full authentication, just tests path reachability and RTT.
func (p *Prober) Probe(ctx context.Context, target string) ProbeResult {
	start := time.Now()
	
	// Create a short-lived context for the dial
	dialCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	// Use a minimal TLS config for probing
	// Use the target host for SNI verification to avoid MITM if possible
	host, _, _ := net.SplitHostPort(target)
	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // Still needed if using self-signed or internal CA
		NextProtos:         []string{"h3", "hivoid/1"},
	}

	// Attempt a QUIC dial
	// We don't need a real UDP conn here as we just want to measure RTT of the first flight
	conn, err := quic.DialAddr(dialCtx, target, tlsCfg, &quic.Config{
		HandshakeIdleTimeout: p.timeout,
		MaxIdleTimeout:       p.timeout,
	})

	rtt := time.Since(start)
	if err != nil {
		return ProbeResult{
			Target:  target,
			Success: false,
			Error:   err,
		}
	}

	// Close immediately — we only cared about the handshake
	_ = conn.CloseWithError(0, "probe done")

	return ProbeResult{
		Target:  target,
		RTT:     rtt,
		Success: true,
	}
}

// ProbeBatch performs concurrent probes on multiple targets.
// ProbeBatch checks multiple targets concurrently and returns results in the same order as input.
func (p *Prober) ProbeBatch(ctx context.Context, targets []string) []ProbeResult {
	results := make([]ProbeResult, len(targets))
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			results[idx] = p.Probe(ctx, target)
		}(i, t)
	}

	wg.Wait()
	return results
}
