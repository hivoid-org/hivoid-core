// Package intelligence implements the HiVoid adaptive decision engine.
// It monitors network conditions in real-time and selects operating modes
// to balance security, performance, and stealth requirements.
package intelligence

import (
	"context"
	"encoding/json"
	"os"
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

// State represents the detected network condition state.
type State uint8

const (
	StateOptimal State = iota
	StateCongested
	StateUnstable
	StateThrottled
	StateBlocked
	StateFallback
)

func (s State) String() string {
	switch s {
	case StateOptimal:
		return "OPTIMAL"
	case StateCongested:
		return "CONGESTED"
	case StateUnstable:
		return "UNSTABLE"
	case StateThrottled:
		return "THROTTLED"
	case StateBlocked:
		return "BLOCKED"
	case StateFallback:
		return "FALLBACK"
	default:
		return "UNKNOWN"
	}
}

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
	stopOnce      sync.Once

	// Statistical history
	history     []MetricsSnapshot
	historySize int

	// Baselines (Long-term averages)
	baselineRTT  time.Duration
	baselineLoss float64

	// Advanced State Machine
	activeState State
	threatLevel int // 0-100
	lastScores  []int
	evalDelay   time.Duration

	// Persistence
	statePath string

	// Active probing
	prober       *Prober
	probeTargets []string
	probeResults []ProbeResult
}

// NewEngine creates a new intelligence engine with the given base mode.
func NewEngine(mode Mode) *Engine {
	e := &Engine{
		configMode:   mode,
		activeMode:   mode,
		activeState:  StateOptimal,
		metrics:      NewMetrics(),
		tuning:       DefaultTuning(),
		stopCh:       make(chan struct{}),
		historySize:  120, // 4 minutes of history
		evalDelay:    2 * time.Second,
		prober:       NewProber(3 * time.Second),
		probeTargets: []string{},
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
	e.stopOnce.Do(func() {
		close(e.stopCh)
		if e.statePath != "" {
			_ = e.SaveState()
		}
	})
}

// Metrics returns the network metrics sampler.
func (e *Engine) Metrics() *Metrics {
	return e.metrics
}

// SetProbeTargets sets the server addresses to periodically check.
func (e *Engine) SetProbeTargets(targets []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.probeTargets = targets
}

// ProbeResults returns the latest results from active probing.
func (e *Engine) ProbeResults() []ProbeResult {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.probeResults
}

// BestTarget selects the healthiest server from probe results using a ranking algorithm.
func (e *Engine) BestTarget() string {
	e.mu.RLock()
	results := append([]ProbeResult(nil), e.probeResults...)
	targets := append([]string(nil), e.probeTargets...)
	e.mu.RUnlock()

	if len(results) == 0 {
		if len(targets) > 0 {
			return targets[0]
		}
		return ""
	}

	type rankedTarget struct {
		target string
		score  float64 // Lower is better
	}

	var ranked []rankedTarget
	for _, r := range results {
		if !r.Success {
			// Penalty for failed probes
			ranked = append(ranked, rankedTarget{r.Target, 100000.0})
			continue
		}

		// Score = RTT (ms) + (Jitter/Variance Penalty)
		// We don't have per-target variance here yet, but we can use RTT as base
		score := float64(r.RTT.Milliseconds())
		ranked = append(ranked, rankedTarget{r.Target, score})
	}

	if len(ranked) == 0 {
		return targets[0]
	}

	// Simple selection of minimum score
	best := ranked[0]
	for _, r := range ranked {
		if r.score < best.score {
			best = r
		}
	}

	return best.target
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

// loop runs evaluations with an adaptive interval.
func (e *Engine) loop() {
	timer := time.NewTimer(e.evalDelay)
	probeTicker := time.NewTicker(15 * time.Second)
	defer timer.Stop()
	defer probeTicker.Stop()

	for {
		select {
		case <-timer.C:
			e.evaluate()
			e.mu.RLock()
			delay := e.evalDelay
			e.mu.RUnlock()
			timer.Reset(delay)
		case <-probeTicker.C:
			e.runProbes()
		case <-e.stopCh:
			return
		}
	}
}

func (e *Engine) runProbes() {
	e.mu.RLock()
	targets := append([]string(nil), e.probeTargets...)
	e.mu.RUnlock()

	if len(targets) == 0 {
		return
	}

	results := e.prober.ProbeBatch(context.Background(), targets)

	e.mu.Lock()
	e.probeResults = results
	e.mu.Unlock()
}

// evaluate reads current metrics and decides if mode/tuning should change.
func (e *Engine) evaluate() {
	snap := e.metrics.Snapshot()
	
	e.mu.Lock()
	e.history = append(e.history, snap)
	if len(e.history) > e.historySize {
		e.history = e.history[1:]
	}
	history := append([]MetricsSnapshot(nil), e.history...)
	probeResults := append([]ProbeResult(nil), e.probeResults...)
	e.mu.Unlock()

	if len(history) < 5 {
		return
	}

	// 1. Calculate Threat Score (0-100)
	score := e.calculateThreatScore(snap, history, probeResults)

	// 2. State Transition Logic
	newState := e.nextState(score, snap, history)

	// 3. Map State to Mode & Tuning
	newMode := e.stateToMode(newState)

	e.mu.Lock()
	oldMode := e.activeMode
	oldState := e.activeState
	e.activeMode = newMode
	e.activeState = newState
	e.threatLevel = score
	
	// Track scores for hysteresis
	e.lastScores = append(e.lastScores, score)
	if len(e.lastScores) > 10 {
		e.lastScores = e.lastScores[1:]
	}
	
	// 4. Adaptive Evaluation Interval
	// In unstable states, evaluate faster
	switch newState {
	case StateBlocked, StateThrottled:
		e.evalDelay = 500 * time.Millisecond
	case StateUnstable:
		e.evalDelay = 1 * time.Second
	default:
		e.evalDelay = 3 * time.Second
	}

	// 5. Update Baselines (Slow EMA)
	if e.baselineRTT == 0 {
		e.baselineRTT = snap.RTT
	} else {
		e.baselineRTT = time.Duration(float64(e.baselineRTT)*0.95 + float64(snap.RTT)*0.05)
	}
	e.baselineLoss = e.baselineLoss*0.98 + snap.PacketLoss*0.02

	e.applyStateTuning(newState, score)
	tuning := e.tuning
	obs := e.observers
	e.mu.Unlock()

	if oldMode != newMode || oldState != newState {
		for _, fn := range obs {
			fn(newMode, tuning)
		}
	}
}

func (e *Engine) calculateThreatScore(snap MetricsSnapshot, history []MetricsSnapshot, probes []ProbeResult) int {
	var score int
	
	brtt := e.baselineRTT
	bloss := e.baselineLoss

	// Factor A: Relative Packet Loss (Max 40 points)
	// If loss is significantly higher than baseline
	lossDelta := snap.PacketLoss - bloss
	if lossDelta > 0.05 {
		score += 20 + int(lossDelta*200)
	}

	// Factor B: RTT Deviation (Max 30 points)
	// Compare current RTT to long-term baseline rather than hardcoded 200ms
	if brtt > 0 {
		ratio := float64(snap.RTT) / float64(brtt)
		if ratio > 3.0 {
			score += 30
		} else if ratio > 1.5 {
			score += 15
		}
	}

	// Factor C: Probe Failures (Max 20 points)
	if len(probes) > 0 {
		failCount := 0
		for _, p := range probes {
			if !p.Success {
				failCount++
			}
		}
		failRatio := float64(failCount) / float64(len(probes))
		score += int(failRatio * 20)
	}

	// Factor D: Jitter/StdDev Anomaly (Max 10 points)
	if snap.RTT > 0 {
		volatility := float64(snap.RTTStdDev) / float64(snap.RTT)
		if volatility > 0.4 {
			score += 10
		}
	}

	if score > 100 {
		return 100
	}
	return score
}

func (e *Engine) nextState(score int, snap MetricsSnapshot, history []MetricsSnapshot) State {
	e.mu.RLock()
	prev := e.activeState
	scores := append([]int(nil), e.lastScores...)
	e.mu.RUnlock()

	// Calculate historical average score for smoothing
	avgScore := score
	if len(scores) > 0 {
		sum := 0
		for _, s := range scores {
			sum += s
		}
		avgScore = sum / len(scores)
	}

	// Hysteresis: To transition into a higher threat state, the current score 
	// must be high. To transition OUT, the average score must drop.
	switch {
	case score >= 90 || (prev == StateFallback && avgScore > 80):
		return StateFallback
	case score >= 75 || (prev == StateBlocked && avgScore > 60):
		return StateBlocked
	case score >= 50 || (prev == StateThrottled && avgScore > 40):
		return StateThrottled
	case score >= 25 || (prev == StateUnstable && avgScore > 20):
		return StateUnstable
	case snap.PacketLoss > 0.02 || (prev == StateCongested && avgScore > 10):
		return StateCongested
	default:
		return StateOptimal
	}
}

func (e *Engine) stateToMode(s State) Mode {
	if e.configMode != ModeAdaptive {
		return e.configMode
	}
	switch s {
	case StateOptimal:
		return ModePerformance
	case StateBlocked, StateThrottled:
		return ModeStealth
	default:
		return ModeBalanced
	}
}

func (e *Engine) applyStateTuning(s State, score int) {
	// Base tuning
	e.tuning = DefaultTuning()

	switch s {
	case StateOptimal:
		e.tuning.StreamConcurrency = 30
		e.tuning.RekeyInterval = 1 * time.Hour
		e.tuning.RTOMultiplier = 0.8

	case StateCongested:
		e.tuning.StreamConcurrency = 10
		e.tuning.RekeyInterval = 30 * time.Minute
		e.tuning.RTOMultiplier = 1.2

	case StateUnstable:
		e.tuning.EnableObfuscation = true
		e.tuning.PaddingPct = 0.3
		e.tuning.MaxPaddingBytes = 128
		e.tuning.StreamConcurrency = 5
		e.tuning.RTOMultiplier = 1.5

	case StateThrottled:
		e.tuning.EnableObfuscation = true
		// Dynamic padding based on threat score
		e.tuning.PaddingPct = 0.4 + (float64(score)/100.0)*0.4
		e.tuning.MaxPaddingBytes = 256 + (score * 5)
		e.tuning.StreamConcurrency = 3
		e.tuning.RekeyInterval = 10 * time.Minute

	case StateBlocked:
		e.tuning.EnableObfuscation = true
		e.tuning.PaddingPct = 0.9
		e.tuning.MaxPaddingBytes = 1024
		e.tuning.StreamConcurrency = 2
		e.tuning.RekeyInterval = 5 * time.Minute
		e.tuning.RTOMultiplier = 2.0

	case StateFallback:
		e.tuning.EnableObfuscation = true
		e.tuning.PaddingPct = 1.0
		e.tuning.MaxPaddingBytes = 1500
		e.tuning.StreamConcurrency = 1
		e.tuning.RekeyInterval = 1 * time.Minute
		e.tuning.RTOMultiplier = 3.0
	}
}

// applyMode sets tuning parameters for fixed modes.
// Must be called with e.mu held.
func (e *Engine) applyMode(mode Mode) {
	switch mode {
	case ModePerformance:
		e.tuning = TuningParams{
			EnableObfuscation: false,
			StreamConcurrency: 30,
			RekeyInterval:     1 * time.Hour,
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
		e.tuning = DefaultTuning()
	}
}

// ActiveState returns the currently detected network state.
func (e *Engine) ActiveState() State {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeState
}

// ThreatLevel returns the current threat score (0-100).
func (e *Engine) ThreatLevel() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.threatLevel
}

// State Persistence Support
type enginePersistence struct {
	BaselineRTT  int64   `json:"baseline_rtt"`
	BaselineLoss float64 `json:"baseline_loss"`
	ThreatLevel  int     `json:"threat_level"`
	ActiveState  uint8   `json:"active_state"`
}

func (e *Engine) ExportState() ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p := enginePersistence{
		BaselineRTT:  int64(e.baselineRTT),
		BaselineLoss: e.baselineLoss,
		ThreatLevel:  e.threatLevel,
		ActiveState:  uint8(e.activeState),
	}
	return json.Marshal(p)
}

func (e *Engine) ImportState(data []byte) error {
	var p enginePersistence
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.baselineRTT = time.Duration(p.BaselineRTT)
	e.baselineLoss = p.BaselineLoss
	e.threatLevel = p.ThreatLevel
	e.activeState = State(p.ActiveState)
	e.applyStateTuning(e.activeState, e.threatLevel)
	return nil
}

// SetStatePath configures the file path for automatic persistence.
func (e *Engine) SetStatePath(path string) {
	e.mu.Lock()
	e.statePath = path
	e.mu.Unlock()
	
	// Try to load initial state
	if data, err := os.ReadFile(path); err == nil {
		_ = e.ImportState(data)
	}
}

// SaveState writes the current engine state to the configured file.
func (e *Engine) SaveState() error {
	e.mu.RLock()
	path := e.statePath
	e.mu.RUnlock()
	
	if path == "" {
		return nil
	}
	
	data, err := e.ExportState()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
