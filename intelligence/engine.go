// Package intelligence implements the HiVoid adaptive decision engine.
// It monitors network conditions in real-time and selects operating modes
// to balance security, performance, and stealth requirements.
package intelligence

import (
	"sync"
	"time"
)

// Mode represents an operating mode for the HiVoid protocol.
type Mode uint8

const (
	// ModePerformance maximizes throughput, minimal overhead.
	ModePerformance Mode = iota
	// ModeStealth enables full obfuscation to avoid traffic analysis.
	ModeStealth
	// ModeBalanced balances performance and security (default).
	ModeBalanced
	// ModeAdaptive auto-switches based on network metrics.
	ModeAdaptive
)

func (m Mode) String() string {
	switch m {
	case ModePerformance:
		return "PERFORMANCE"
	case ModeStealth:
		return "STEALTH"
	case ModeBalanced:
		return "BALANCED"
	case ModeAdaptive:
		return "ADAPTIVE"
	default:
		return "UNKNOWN"
	}
}

// ModeFromString parses a mode name string.
func ModeFromString(s string) Mode {
	switch toLowerASCII(s) {
	case "performance":
		return ModePerformance
	case "high_performance":
		return ModePerformance
	case "stealth":
		return ModeStealth
	case "balanced":
		return ModeBalanced
	case "adaptive":
		return ModeAdaptive
	default:
		return ModeAdaptive
	}
}

// SetMode updates the configured mode at runtime.
// It is safe for concurrent use.
func (e *Engine) SetMode(mode Mode) {
	e.mu.Lock()
	e.configMode = mode
	e.activeMode = mode
	e.applyMode(mode)
	tuning := e.tuning
	obs := append([]func(Mode, TuningParams){}, e.observers...)
	e.mu.Unlock()

	for _, fn := range obs {
		fn(mode, tuning)
	}
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// TuningParams holds the output parameters from engine decisions.
// These are applied to the transport and obfuscation layers.
type TuningParams struct {
	// EnableObfuscation activates the obfuscation layer.
	EnableObfuscation bool
	// PaddingPct is the fraction of frames that get random padding [0,1].
	PaddingPct float64
	// MaxPaddingBytes is the maximum padding to add per frame.
	MaxPaddingBytes int
	// StreamConcurrency is the max number of concurrent QUIC streams.
	StreamConcurrency int
	// RekeyInterval controls how often keys are rotated.
	RekeyInterval time.Duration
	// RTOMultiplier scales the retransmission timeout.
	RTOMultiplier float64
}

// DefaultTuning returns sane defaults for ModeBalanced.
func DefaultTuning() TuningParams {
	return TuningParams{
		EnableObfuscation: false,
		PaddingPct:        0.0,
		MaxPaddingBytes:   0,
		StreamConcurrency: 10,
		RekeyInterval:     10 * time.Minute,
		RTOMultiplier:     1.0,
	}
}

// Engine is the HiVoid intelligence decision engine.
// It continuously samples network metrics and adjusts tuning parameters.
type Engine struct {
	mu            sync.RWMutex
	configMode    Mode    // User-configured mode
	activeMode    Mode    // Currently active mode (may differ in ADAPTIVE)
	metrics       *Metrics
	tuning        TuningParams
	observers     []func(Mode, TuningParams)
	stopCh        chan struct{}
}

// NewEngine creates a new intelligence engine with the given base mode.
func NewEngine(mode Mode) *Engine {
	e := &Engine{
		configMode: mode,
		activeMode: mode,
		metrics:    NewMetrics(),
		tuning:     DefaultTuning(),
		stopCh:     make(chan struct{}),
	}

	// Apply initial mode
	e.applyMode(mode)
	return e
}

// Start begins the background decision loop.
func (e *Engine) Start() {
	go e.loop()
}

// Stop halts the background decision loop.
func (e *Engine) Stop() {
	close(e.stopCh)
}

// Metrics returns the network metrics sampler.
func (e *Engine) Metrics() *Metrics {
	return e.metrics
}

// Tuning returns the current tuning parameters (safe for concurrent use).
func (e *Engine) Tuning() TuningParams {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.tuning
}

// ActiveMode returns the currently active mode.
func (e *Engine) ActiveMode() Mode {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeMode
}

// OnModeChange registers a callback invoked when the mode changes.
func (e *Engine) OnModeChange(fn func(Mode, TuningParams)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.observers = append(e.observers, fn)
}

// loop runs every 2 seconds and re-evaluates the network conditions.
func (e *Engine) loop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.evaluate()
		case <-e.stopCh:
			return
		}
	}
}

// evaluate reads current metrics and decides if mode/tuning should change.
func (e *Engine) evaluate() {
	if e.configMode != ModeAdaptive {
		// Fixed mode — just re-apply tuning in case metrics changed
		return
	}

	snap := e.metrics.Snapshot()
	newMode := e.decide(snap)

	e.mu.Lock()
	old := e.activeMode
	e.activeMode = newMode
	e.applyMode(newMode)
	tuning := e.tuning
	obs := e.observers
	e.mu.Unlock()

	if old != newMode {
		for _, fn := range obs {
			fn(newMode, tuning)
		}
	}
}

// decide implements the core decision logic.
//
//	Decision matrix:
//	  packet_loss > 10%     → STEALTH (resilient + obfuscation reduces handshake retries)
//	  rtt > 200ms           → PERFORMANCE (minimize overhead)
//	  jitter > 50ms         → BALANCED
//	  suspicious traffic    → STEALTH
//	  otherwise             → BALANCED
func (e *Engine) decide(snap MetricsSnapshot) Mode {
	switch {
	case snap.PacketLoss > 0.10:
		// High loss: use stealth to reduce retransmission fingerprinting
		return ModeStealth
	case snap.RTT > 200*time.Millisecond:
		// High latency: minimize overhead for performance
		return ModePerformance
	case snap.Jitter > 50*time.Millisecond:
		// Unstable network: balanced approach
		return ModeBalanced
	default:
		return ModeBalanced
	}
}

// applyMode sets tuning parameters for the given mode.
// Must be called with e.mu held.
func (e *Engine) applyMode(mode Mode) {
	switch mode {
	case ModePerformance:
		e.tuning = TuningParams{
			EnableObfuscation: false,
			PaddingPct:        0.0,
			MaxPaddingBytes:   0,
			StreamConcurrency: 20,
			RekeyInterval:     30 * time.Minute,
			RTOMultiplier:     0.8,
		}
	case ModeStealth:
		e.tuning = TuningParams{
			EnableObfuscation: true,
			PaddingPct:        0.8,
			MaxPaddingBytes:   512,
			StreamConcurrency: 5,
			RekeyInterval:     5 * time.Minute,
			RTOMultiplier:     1.5,
		}
	case ModeBalanced:
		e.tuning = TuningParams{
			EnableObfuscation: false,
			PaddingPct:        0.2,
			MaxPaddingBytes:   128,
			StreamConcurrency: 10,
			RekeyInterval:     10 * time.Minute,
			RTOMultiplier:     1.0,
		}
	case ModeAdaptive:
		// ADAPTIVE starts at balanced; evaluate() will switch as needed
		e.tuning = DefaultTuning()
	}
}
