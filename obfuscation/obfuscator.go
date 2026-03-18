// Package obfuscation implements the HiVoid traffic obfuscation layer.
//
// Goals:
//   - Prevent traffic analysis by avoiding static packet size patterns
//   - Add timing jitter to defeat timing-correlation attacks
//   - Shape bursts to avoid obvious protocol fingerprints
//
// The obfuscation layer sits between the session layer (which produces
// encrypted frames) and the QUIC transport. It wraps frames before
// writing and strips padding before delivering to the session layer.
package obfuscation

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/hivoid-org/hivoid-core/frames"
)

// Config controls obfuscation behavior.
type Config struct {
	// Enabled toggles obfuscation. When false, all methods are no-ops.
	Enabled bool
	// PaddingPct is the probability [0,1] that a frame gets padding added.
	PaddingPct float64
	// MaxPaddingBytes is the upper bound on random padding per frame.
	MaxPaddingBytes int
	// MaxJitterMs is the maximum additional send delay in milliseconds.
	MaxJitterMs int
	// BurstWindow is the duration over which burst shaping is applied.
	BurstWindow time.Duration
	// BurstBytesMax limits bytes sent within BurstWindow.
	BurstBytesMax int64
}

// DefaultConfig returns a conservative obfuscation configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:         false,
		PaddingPct:      0.3,
		MaxPaddingBytes: 256,
		MaxJitterMs:     5,
		BurstWindow:     100 * time.Millisecond,
		BurstBytesMax:   64 * 1024,
	}
}

// Obfuscator transforms frames to resist traffic analysis.
type Obfuscator struct {
	cfg Config

	// Burst control state
	burstStart time.Time
	burstBytes int64
}

// New creates an Obfuscator with the given configuration.
func New(cfg Config) *Obfuscator {
	return &Obfuscator{cfg: cfg, burstStart: time.Now()}
}

// Update applies new configuration (e.g., from intelligence engine).
func (o *Obfuscator) Update(cfg Config) {
	o.cfg = cfg
}

// Wrap takes an encrypted frame and optionally adds padding.
// Returns a new frame with FlagPadded set if padding was added,
// or the original frame unchanged if obfuscation is disabled.
func (o *Obfuscator) Wrap(f *frames.Frame) (*frames.Frame, error) {
	if !o.cfg.Enabled {
		return f, nil
	}

	// Decide whether to pad this frame
	if o.cfg.PaddingPct > 0 && o.cfg.MaxPaddingBytes > 0 {
		roll, err := randFloat()
		if err != nil {
			return nil, fmt.Errorf("rng: %w", err)
		}
		if roll < o.cfg.PaddingPct {
			return o.addPadding(f)
		}
	}
	return f, nil
}

// Unwrap strips padding from a received frame.
// Padding format appended to payload: [pad_len:2][random_bytes:pad_len]
func (o *Obfuscator) Unwrap(f *frames.Frame) (*frames.Frame, error) {
	if !f.HasFlag(frames.FlagPadded) {
		return f, nil
	}

	payload := f.Payload
	if len(payload) < 2 {
		return nil, fmt.Errorf("padded frame too short")
	}

	// Last 2 bytes of payload are pad_len
	padLen := int(payload[len(payload)-2])<<8 | int(payload[len(payload)-1])
	totalPad := padLen + 2
	if totalPad > len(payload) {
		return nil, fmt.Errorf("invalid padding length %d in payload of %d bytes", padLen, len(payload))
	}

	// Strip padding: original data is everything before the padding
	orig := make([]byte, len(payload)-totalPad)
	copy(orig, payload[:len(payload)-totalPad])

	result := &frames.Frame{
		Type:    f.Type,
		Flags:   f.Flags &^ frames.FlagPadded,
		Payload: orig,
	}
	return result, nil
}

// ApplyJitter sleeps for a random duration up to MaxJitterMs milliseconds.
// This adds timing noise to outbound frames, disrupting timing analysis.
func (o *Obfuscator) ApplyJitter() {
	if !o.cfg.Enabled || o.cfg.MaxJitterMs <= 0 {
		return
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(o.cfg.MaxJitterMs)*int64(time.Millisecond)))
	if err != nil {
		return
	}
	time.Sleep(time.Duration(n.Int64()))
}

// CheckBurst enforces burst-rate limiting. If the burst window is exhausted,
// it sleeps until the next window starts. Returns immediately on low traffic.
func (o *Obfuscator) CheckBurst(frameBytes int64) {
	if !o.cfg.Enabled || o.cfg.BurstBytesMax <= 0 {
		return
	}
	now := time.Now()
	if now.Sub(o.burstStart) >= o.cfg.BurstWindow {
		// New window
		o.burstStart = now
		o.burstBytes = 0
	}
	o.burstBytes += frameBytes
	if o.burstBytes > o.cfg.BurstBytesMax {
		// Sleep until next window
		sleepTime := o.cfg.BurstWindow - now.Sub(o.burstStart)
		if sleepTime > 0 {
			time.Sleep(sleepTime)
		}
		o.burstStart = time.Now()
		o.burstBytes = frameBytes
	}
}

// addPadding appends random bytes to the frame payload.
// Padding structure: [original_payload][random_pad][pad_len:2]
func (o *Obfuscator) addPadding(f *frames.Frame) (*frames.Frame, error) {
	padLen, err := randIntN(o.cfg.MaxPaddingBytes + 1)
	if err != nil {
		return nil, fmt.Errorf("pad rng: %w", err)
	}
	if padLen == 0 {
		return f, nil
	}

	padding := make([]byte, padLen)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return nil, fmt.Errorf("generate padding: %w", err)
	}

	// Append: original || random_padding || pad_len_hi || pad_len_lo
	newPayload := make([]byte, len(f.Payload)+padLen+2)
	copy(newPayload, f.Payload)
	copy(newPayload[len(f.Payload):], padding)
	newPayload[len(newPayload)-2] = byte(padLen >> 8)
	newPayload[len(newPayload)-1] = byte(padLen)

	result := &frames.Frame{
		Type:    f.Type,
		Flags:   f.Flags | frames.FlagPadded,
		Payload: newPayload,
	}
	return result, nil
}

// randFloat returns a uniform random float64 in [0, 1).
func randFloat() (float64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return 0, err
	}
	return float64(n.Int64()) / 1_000_000.0, nil
}

// randIntN returns a uniform random integer in [0, n).
func randIntN(n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}
