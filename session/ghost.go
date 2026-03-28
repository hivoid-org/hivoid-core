// Package session implements the Ghost Constant Bitrate (CBR) Engine.
// Ghost achieves statistical undetectability by enforcing an isochronous
// transmission schedule with fixed-size frames, masking application
// traffic patterns from DPI/statistical analysis.
package session

import (
	"crypto/rand"
	"io"
	"sync"
	"time"

	"github.com/hivoid-org/hivoid-core/frames"
	"github.com/quic-go/quic-go"
)

const (
	// GhostDefaultFrameSize is the MTU-optimized payload size for all frames.
	GhostDefaultFrameSize = 1024

	// GhostMaxQueueSize bounds memory usage under congestion.
	GhostMaxQueueSize = 2048
)

// ghostEngine manages the isochronous traffic loop.
type ghostEngine struct {
	sess   *Session
	mu     sync.Mutex
	queue  [][]byte      // Pending normalized data chunks
	stopCh chan struct{}
	
	stream *quic.Stream   // Persistent stream to minimize DPI fingerprinting
}

// newGhostEngine initializes the CBR engine for the given session.
func newGhostEngine(s *Session) *ghostEngine {
	return &ghostEngine{
		sess:   s,
		queue:  make([][]byte, 0, 64),
		stopCh: make(chan struct{}),
	}
}

// Enqueue fragments and normalizes data for isochronous transmission.
func (g *ghostEngine) Enqueue(data []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()

	for len(data) > 0 {
		if len(g.queue) >= GhostMaxQueueSize {
			break // Congestion control: drop oldest/overflow
		}

		chunk := data
		if len(chunk) > GhostDefaultFrameSize {
			chunk = data[:GhostDefaultFrameSize]
		}
		
		normalized := make([]byte, GhostDefaultFrameSize)
		copy(normalized, chunk)
		if len(chunk) < GhostDefaultFrameSize {
			// Fill remainder with cryptographic noise
			_, _ = io.ReadFull(rand.Reader, normalized[len(chunk):])
		}
		g.queue = append(g.queue, normalized)
		data = data[len(chunk):]
	}
}

// randomJitter returns cryptographically secure random milliseconds.
func randomJitter(maxMs int64) time.Duration {
	if maxMs <= 0 {
		return 0
	}
	b := make([]byte, 2)
	_, _ = io.ReadFull(rand.Reader, b)
	val := int64(b[0])<<8 | int64(b[1])
	return time.Duration(val%maxMs) * time.Millisecond
}

// Run executes the transmission loop. Must be called as a goroutine.
// Instead of a strict CBR, it uses Dynamic CBR (Adaptive Jitter) to evade fingerprinting.
func (g *ghostEngine) Run() {
	for {
		g.mu.Lock()
		qLen := len(g.queue)
		g.mu.Unlock()

		var nextInterval time.Duration
		if qLen > 100 {
			// High load (Streaming/Download): Low latency, high throughput (approx 100 PPS)
			nextInterval = 10 * time.Millisecond
		} else if qLen > 10 {
			// Medium load (Web browsing): Normal throughput with slight jitter
			nextInterval = 30*time.Millisecond + randomJitter(10)
		} else {
			// Idle load (Background): High noise jitter to break statistical CBR signatures
			// and reduce unneeded noise bandwidth. Base 100ms + random up to 150ms.
			nextInterval = 100*time.Millisecond + randomJitter(150)
		}

		select {
		case <-g.stopCh:
			return
		case <-g.sess.ctx.Done():
			return
		case <-time.After(nextInterval):
			g.tick()
		}
	}
}

// Stop terminates the CBR loop safely.
func (g *ghostEngine) Stop() {
	select {
	case <-g.stopCh:
	default:
		close(g.stopCh)
	}
}

// tick transmits exactly one frame (real data or noise).
func (g *ghostEngine) tick() {
	g.mu.Lock()
	var payload []byte
	isNoise := false
	if len(g.queue) > 0 {
		payload = g.queue[0]
		g.queue = g.queue[1:]
	} else {
		// Generate cryptographic noise
		payload = make([]byte, GhostDefaultFrameSize)
		_, _ = io.ReadFull(rand.Reader, payload)
		isNoise = true
	}
	g.mu.Unlock()

	// Maintain persistent stream to avoid per-packet connection overhead
	if g.stream == nil {
		stream, err := g.sess.conn.OpenStreamSync(g.sess.ctx)
		if err != nil {
			return 
		}
		g.stream = stream
	}

	var f *frames.Frame
	if isNoise {
		f = &frames.Frame{
			Type:    frames.FrameNoise,
			Flags:   0,
			Payload: payload,
		}
	} else {
		f = frames.NewDataFrame(payload, true)
	}

	_, err := f.WriteTo(g.stream)
	if err != nil {
		g.stream.Close()
		g.stream = nil
	}

	// Update traffic counters (even noise counts to maintain accurate stats)
	g.sess.TrafficSent.Add(uint64(len(payload)))
}

// isGhostNoise identifies and discards chaff frames at the receiver.
func isGhostNoise(stream *quic.Stream) bool {
	// Peek type byte without consuming full payload
	header := make([]byte, 1)
	_, err := io.ReadFull(stream, header)
	if err != nil {
		stream.Close()
		return false
	}
	
	isNoise := frames.FrameType(header[0]) == frames.FrameNoise
	if isNoise {
		stream.Close()
	}
	return isNoise
}
