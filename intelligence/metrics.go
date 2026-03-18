// Package intelligence — real-time network metrics collection.
// These are fed into the decision engine for adaptive mode switching.
package intelligence

import (
	"sync"
	"sync/atomic"
	"time"
)

// MetricsSnapshot is a point-in-time view of the collected metrics.
type MetricsSnapshot struct {
	RTT        time.Duration
	Jitter     time.Duration
	PacketLoss float64 // [0, 1]
	Throughput int64   // bytes/sec
	SampledAt  time.Time
}

// Metrics is a thread-safe collector of QUIC-level network statistics.
// Values are updated by the transport layer via RecordRTT / RecordLoss / RecordBytes.
type Metrics struct {
	mu sync.RWMutex

	// RTT exponential moving average (nanoseconds stored as int64)
	rttEMA atomic.Int64

	// Jitter EMA
	jitterEMA atomic.Int64

	// Loss counters
	sentPkts atomic.Int64
	lostPkts atomic.Int64

	// Throughput tracking
	bytesInWindow atomic.Int64
	windowStart   time.Time

	// Last snapshot
	lastSnap MetricsSnapshot
}

// NewMetrics creates a zeroed Metrics instance.
func NewMetrics() *Metrics {
	m := &Metrics{windowStart: time.Now()}
	// Set initial RTT to a realistic starting value
	m.rttEMA.Store(int64(20 * time.Millisecond))
	return m
}

const emaAlpha = 0.125 // EWMA smoothing factor (same as Linux TCP)

// RecordRTT updates the RTT exponential moving average.
// rtt should be the measured round-trip time for a recent packet.
func (m *Metrics) RecordRTT(rtt time.Duration) {
	prev := time.Duration(m.rttEMA.Load())
	delta := rtt - prev
	if delta < 0 {
		delta = -delta
	}
	// Update jitter EMA
	prevJitter := time.Duration(m.jitterEMA.Load())
	newJitter := time.Duration(float64(prevJitter) + emaAlpha*float64(delta-prevJitter))
	m.jitterEMA.Store(int64(newJitter))

	// Update RTT EMA
	newRTT := time.Duration(float64(prev) + emaAlpha*float64(rtt-prev))
	m.rttEMA.Store(int64(newRTT))
}

// RecordPacketSent increments the sent packet counter.
func (m *Metrics) RecordPacketSent() {
	m.sentPkts.Add(1)
}

// RecordPacketLost increments the lost packet counter.
func (m *Metrics) RecordPacketLost() {
	m.lostPkts.Add(1)
}

// RecordBytes records n bytes transferred for throughput calculation.
func (m *Metrics) RecordBytes(n int64) {
	m.bytesInWindow.Add(n)
}

// Snapshot returns a point-in-time view of all metrics.
// It refreshes the throughput window if needed.
func (m *Metrics) Snapshot() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	sent := m.sentPkts.Load()
	lost := m.lostPkts.Load()
	var loss float64
	if sent > 0 {
		loss = float64(lost) / float64(sent)
	}

	// Throughput: bytes in this window / seconds elapsed
	now := time.Now()
	elapsed := now.Sub(m.windowStart).Seconds()
	var throughput int64
	if elapsed > 0 {
		throughput = int64(float64(m.bytesInWindow.Load()) / elapsed)
	}

	// Roll the window every 5 seconds
	if elapsed >= 5 {
		m.bytesInWindow.Store(0)
		m.windowStart = now
		// Reset loss counters rolling window
		m.sentPkts.Store(0)
		m.lostPkts.Store(0)
	}

	snap := MetricsSnapshot{
		RTT:        time.Duration(m.rttEMA.Load()),
		Jitter:     time.Duration(m.jitterEMA.Load()),
		PacketLoss: loss,
		Throughput: throughput,
		SampledAt:  now,
	}
	m.lastSnap = snap
	return snap
}
