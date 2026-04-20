// Package intelligence — real-time network metrics collection.
// These are fed into the decision engine for adaptive mode switching.
package intelligence

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsSnapshot is a point-in-time view of the collected metrics.
type MetricsSnapshot struct {
	RTT        time.Duration
	RTTStdDev  time.Duration
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

	// RTT Variance (Welford's algorithm parameters)
	rttMean atomic.Int64
	rttM2    atomic.Int64
	count    atomic.Int64

	// Loss counters (Combined into one uint64: sent [hi 32] | lost [lo 32])
	pktStats atomic.Uint64

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
	val := int64(rtt)
	prev := m.rttEMA.Load()
	
	// Update EMA
	delta := val - prev
	if delta < 0 {
		delta = -delta
	}
	prevJitter := m.jitterEMA.Load()
	newJitter := int64(float64(prevJitter) + emaAlpha*float64(delta-prevJitter))
	m.jitterEMA.Store(newJitter)

	newRTT := int64(float64(prev) + emaAlpha*float64(val-prev))
	m.rttEMA.Store(newRTT)

	// Update Variance using Welford's Online Algorithm
	m.mu.Lock()
	m.count.Add(1)
	n := float64(m.count.Load())
	
	fval := float64(val)
	fmean := float64(m.rttMean.Load())
	fm2 := float64(m.rttM2.Load())

	fDelta := fval - fmean
	newMean := fmean + fDelta/n
	m.rttMean.Store(int64(newMean))
	
	delta2 := fval - newMean
	newM2 := fm2 + fDelta*delta2
	m.rttM2.Store(int64(newM2))
	m.mu.Unlock()
}

// RecordPacketSent increments the sent packet counter.
func (m *Metrics) RecordPacketSent() {
	m.pktStats.Add(uint64(1) << 32)
}

// RecordPacketLost increments the lost packet counter.
func (m *Metrics) RecordPacketLost() {
	m.pktStats.Add(1)
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

	// Atomic read and reset of loss counters
	now := time.Now()
	elapsed := now.Sub(m.windowStart).Seconds()
	
	var stats uint64
	if elapsed >= 5 {
		stats = m.pktStats.Swap(0)
		m.bytesInWindow.Store(0)
		m.windowStart = now
	} else {
		stats = m.pktStats.Load()
	}

	sent := uint32(stats >> 32)
	lost := uint32(stats & 0xFFFFFFFF)
	
	var loss float64
	if sent > 0 {
		loss = float64(lost) / float64(sent)
	}

	// Throughput calculation
	var throughput int64
	if elapsed > 0 {
		throughput = int64(float64(m.bytesInWindow.Load()) / elapsed)
	}

	// Calculate standard deviation
	var rttStdDev time.Duration
	count := m.count.Load()
	if count > 1 {
		variance := float64(m.rttM2.Load()) / float64(count-1)
		rttStdDev = time.Duration(math.Sqrt(variance))
	}

	snap := MetricsSnapshot{
		RTT:        time.Duration(m.rttEMA.Load()),
		RTTStdDev:  rttStdDev,
		Jitter:     time.Duration(m.jitterEMA.Load()),
		PacketLoss: loss,
		Throughput: throughput,
		SampledAt:  now,
	}
	m.lastSnap = snap
	return snap
}
