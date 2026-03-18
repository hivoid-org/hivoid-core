// Package obfuscation — unit tests for the obfuscation layer.
package obfuscation

import (
	"testing"

	"github.com/hivoid-org/hivoid-core/frames"
)

// TestWrapUnwrapPadded verifies that adding and removing padding is lossless.
func TestWrapUnwrapPadded(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		PaddingPct:      1.0, // always pad
		MaxPaddingBytes: 256,
		MaxJitterMs:     0, // no delay in tests
	}
	o := New(cfg)

	original := &frames.Frame{
		Type:    frames.FrameData,
		Flags:   frames.FlagEncrypted,
		Payload: []byte("test payload data"),
	}

	// Wrap multiple times to exercise random padding sizes
	for i := 0; i < 20; i++ {
		wrapped, err := o.Wrap(original)
		if err != nil {
			t.Fatalf("Wrap %d: %v", i, err)
		}

		// Wrapped frame must be at least as long as original
		if len(wrapped.Payload) < len(original.Payload) {
			t.Errorf("wrapped payload is shorter than original")
		}

		// Unwrap
		unwrapped, err := o.Unwrap(wrapped)
		if err != nil {
			t.Fatalf("Unwrap %d: %v", i, err)
		}

		if string(unwrapped.Payload) != string(original.Payload) {
			t.Errorf("payload mismatch after wrap/unwrap: got %q, want %q",
				unwrapped.Payload, original.Payload)
		}

		// FlagPadded should be cleared after unwrap
		if unwrapped.HasFlag(frames.FlagPadded) {
			t.Error("FlagPadded should not be set after Unwrap")
		}
	}
}

// TestWrapDisabled verifies frame passes through unchanged when disabled.
func TestWrapDisabled(t *testing.T) {
	o := New(Config{Enabled: false})
	f := &frames.Frame{
		Type:    frames.FrameData,
		Payload: []byte("unchanged"),
	}
	wrapped, err := o.Wrap(f)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped != f {
		t.Error("expected same frame pointer when disabled")
	}
}

// TestUnwrapNoPadding verifies that frames without FlagPadded are returned unchanged.
func TestUnwrapNoPadding(t *testing.T) {
	o := New(DefaultConfig())
	f := &frames.Frame{
		Type:    frames.FrameData,
		Payload: []byte("no padding here"),
	}
	result, err := o.Unwrap(f)
	if err != nil {
		t.Fatal(err)
	}
	if result != f {
		t.Error("expected same frame when no padding flag")
	}
}

// TestZeroPaddingPct verifies that PaddingPct=0 never adds padding.
func TestZeroPaddingPct(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		PaddingPct:      0.0,
		MaxPaddingBytes: 256,
	}
	o := New(cfg)
	f := &frames.Frame{
		Type:    frames.FrameData,
		Payload: []byte("should not be padded"),
	}
	for i := 0; i < 50; i++ {
		wrapped, err := o.Wrap(f)
		if err != nil {
			t.Fatal(err)
		}
		if wrapped.HasFlag(frames.FlagPadded) {
			t.Error("frame was padded when PaddingPct=0")
		}
	}
}
