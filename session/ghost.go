// Package session — Ghost Constant Bitrate (CBR) Engine.
//
// The Ghost engine generates a perfectly uniform traffic signature by:
//   1. Normalizing all transmitted frames to a fixed size (GhostFrameSize bytes)
//   2. Transmitting at a fixed interval (GhostTickInterval), injecting FrameNoise
//      when no real data is available
//   3. Silently discarding received FrameNoise on the remote side
//
// From the perspective of a DPI observer, the tunnel appears as a constant
// stream of identically-sized, evenly-spaced encrypted UDP packets — providing
// no statistical signal to distinguish it from background noise.
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
	// GhostFrameSize is the exact payload size for every Ghost-mode frame.
	// Chosen to fit within a single QUIC packet after headers/encryption overhead.
	GhostFrameSize = 1024

	// GhostTickInterval is the fixed interval between consecutive packets.
	// 40ms = 25 packets/sec ≈ 25 KB/s idle bandwidth.
	GhostTickInterval = 40 * time.Millisecond
)

// ghostEngine manages the isochronous (constant bitrate) traffic loop.
type ghostEngine struct {
	sess   *Session
	mu     sync.Mutex
	queue  [][]byte      // buffered real data chunks ready to send
	stopCh chan struct{}
}

// newGhostEngine creates but does not start the CBR engine.
func newGhostEngine(s *Session) *ghostEngine {
	return &ghostEngine{
		sess:   s,
		queue:  make([][]byte, 0, 64),
		stopCh: make(chan struct{}),
	}
}

// Enqueue buffers a real data chunk for transmission at the next tick.
// Data larger than GhostFrameSize is chunked automatically.
func (g *ghostEngine) Enqueue(data []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Chunk data into GhostFrameSize-sized pieces
	for len(data) > 0 {
		chunk := data
		if len(chunk) > GhostFrameSize {
			chunk = data[:GhostFrameSize]
		}
		// Normalize to exact size: pad if shorter
		normalized := make([]byte, GhostFrameSize)
		copy(normalized, chunk)
		if len(chunk) < GhostFrameSize {
			// Fill remainder with cryptographic noise
			_, _ = io.ReadFull(rand.Reader, normalized[len(chunk):])
		}
		g.queue = append(g.queue, normalized)
		data = data[len(chunk):]
	}
}

// Run starts the isochronous transmission loop.
// It MUST be launched as a goroutine: go engine.Run()
func (g *ghostEngine) Run() {
	ticker := time.NewTicker(GhostTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-g.stopCh:
			return
		case <-g.sess.ctx.Done():
			return
		case <-ticker.C:
			g.tick()
		}
	}
}

// Stop terminates the CBR loop.
func (g *ghostEngine) Stop() {
	select {
	case <-g.stopCh:
	default:
		close(g.stopCh)
	}
}

// tick sends exactly one frame per interval:
// - A real data frame if the queue has data
// - A FrameNoise frame otherwise
func (g *ghostEngine) tick() {
	g.mu.Lock()
	var payload []byte
	isNoise := false
	if len(g.queue) > 0 {
		payload = g.queue[0]
		g.queue = g.queue[1:]
	} else {
		// Generate cryptographic noise
		payload = make([]byte, GhostFrameSize)
		_, _ = io.ReadFull(rand.Reader, payload)
		isNoise = true
	}
	g.mu.Unlock()

	// Open a stream and send the frame
	stream, err := g.sess.conn.OpenStreamSync(g.sess.ctx)
	if err != nil {
		return // connection is closing
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

	_, _ = f.WriteTo(stream)
	_ = stream.Close()

	// Update traffic counters (even noise counts to maintain accurate stats)
	g.sess.TrafficSent.Add(uint64(len(payload)))
}

// isGhostNoise checks if an incoming stream carries a noise frame that should be
// silently discarded. Used by the session receiver to filter Ghost chaff.
func isGhostNoise(stream quic.Stream) bool {
	// Peek at the frame type byte without consuming the stream.
	// Frame header: [Type(1)] [Flags(1)] [Length(4)] [Payload...]
	header := make([]byte, 1)
	_, err := io.ReadFull(stream, header)
	if err != nil {
		return false
	}
	return frames.FrameType(header[0]) == frames.FrameNoise
}
