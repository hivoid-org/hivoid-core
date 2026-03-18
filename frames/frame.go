// Package frames defines the HiVoid wire protocol frame format.
//
// Frame wire format (over QUIC streams):
//
//	┌──────────┬──────────────┬─────────────────────┬───────────────────────┐
//	│ Type (1B)│ Flags (1B)   │ Length (4B, big-end)│ Payload (Length bytes)│
//	└──────────┴──────────────┴─────────────────────┴───────────────────────┘
//
// Frames are multiplexed over QUIC streams. The control stream (stream 0)
// carries CONTROL, REKEY, SIGNAL, and SESSION_UPDATE frames.
// Data streams (stream 1+) carry DATA frames.
package frames

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// FrameType identifies the purpose of a frame.
type FrameType uint8

const (
	// FrameData carries application payload (encrypted).
	FrameData FrameType = 0x01
	// FrameControl carries session control messages.
	FrameControl FrameType = 0x02
	// FrameRekey signals and carries key rotation material.
	FrameRekey FrameType = 0x03
	// FrameSignal carries intelligence/state signals.
	FrameSignal FrameType = 0x04
	// FrameSessionUpdate carries session parameter updates.
	FrameSessionUpdate FrameType = 0x05
	// FramePing is for RTT measurement.
	FramePing FrameType = 0x06
	// FramePong is the RTT response.
	FramePong FrameType = 0x07
	// FrameProxy carries proxy tunnel negotiation (ProxyRequest / ProxyResponse).
	// The first frame on any tunnel stream must be FrameProxy.
	FrameProxy FrameType = 0x08
)

// FrameFlag bitfield for frame metadata.
type FrameFlag uint8

const (
	// FlagEncrypted indicates the payload is AEAD-encrypted.
	FlagEncrypted FrameFlag = 1 << 0
	// FlagCompressed indicates the payload is compressed (reserved).
	FlagCompressed FrameFlag = 1 << 1
	// FlagFinal indicates this is the last frame in a stream.
	FlagFinal FrameFlag = 1 << 2
	// FlagPadded indicates the frame payload has been padded for obfuscation.
	FlagPadded FrameFlag = 1 << 3
)

const (
	// HeaderSize is the fixed header size: 1 (type) + 1 (flags) + 4 (length)
	HeaderSize = 6
	// MaxPayloadSize limits individual frame payloads to prevent abuse.
	MaxPayloadSize = 4 * 1024 * 1024 // 4 MB
)

// Frame is the fundamental unit of communication in HiVoid.
type Frame struct {
	Type    FrameType
	Flags   FrameFlag
	Payload []byte
}

// HasFlag returns true if the given flag is set.
func (f *Frame) HasFlag(flag FrameFlag) bool {
	return f.Flags&flag != 0
}

// SetFlag sets the given flag bit.
func (f *Frame) SetFlag(flag FrameFlag) {
	f.Flags |= flag
}

// Encode serializes the frame into bytes ready for writing to a QUIC stream.
// Format: [type:1][flags:1][len:4][payload:len]
func (f *Frame) Encode() []byte {
	buf := make([]byte, HeaderSize+len(f.Payload))
	buf[0] = byte(f.Type)
	buf[1] = byte(f.Flags)
	binary.BigEndian.PutUint32(buf[2:6], uint32(len(f.Payload)))
	copy(buf[6:], f.Payload)
	return buf
}

// WriteTo encodes and writes the full frame directly to an io.Writer.
// Handles short writes to avoid truncating frames on stream backpressure.
func (f *Frame) WriteTo(w io.Writer) (int64, error) {
	b := f.Encode()
	n, err := writeFull(w, b)
	return int64(n), err
}

func writeFull(w io.Writer, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := w.Write(b[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

// Decode reads exactly one frame from the reader.
// It is safe to call from multiple goroutines on separate streams (not the same stream).
func Decode(r io.Reader) (*Frame, error) {
	// Read the fixed header
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("read header: %w", err)
	}

	frameType := FrameType(header[0])
	flags := FrameFlag(header[1])
	payloadLen := binary.BigEndian.Uint32(header[2:6])

	// Guard against oversized frames
	if payloadLen > MaxPayloadSize {
		return nil, fmt.Errorf("frame payload too large: %d > %d", payloadLen, MaxPayloadSize)
	}

	// Read payload
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return &Frame{
		Type:    frameType,
		Flags:   flags,
		Payload: payload,
	}, nil
}

// NewDataFrame creates a DATA frame with the given encrypted payload.
func NewDataFrame(payload []byte, final bool) *Frame {
	f := &Frame{
		Type:    FrameData,
		Payload: payload,
	}
	f.SetFlag(FlagEncrypted)
	if final {
		f.SetFlag(FlagFinal)
	}
	return f
}

// NewControlFrame creates a CONTROL frame with a structured payload.
func NewControlFrame(payload []byte) *Frame {
	return &Frame{
		Type:    FrameControl,
		Payload: payload,
	}
}

// NewRekeyFrame creates a REKEY frame carrying new key material.
func NewRekeyFrame(payload []byte) *Frame {
	return &Frame{
		Type:    FrameRekey,
		Payload: payload,
	}
}

// NewPingFrame creates a PING frame with an 8-byte timestamp payload.
func NewPingFrame(timestamp []byte) *Frame {
	return &Frame{
		Type:    FramePing,
		Payload: timestamp,
	}
}

// NewPongFrame creates a PONG reply copying the ping payload.
func NewPongFrame(pingPayload []byte) *Frame {
	cp := make([]byte, len(pingPayload))
	copy(cp, pingPayload)
	return &Frame{
		Type:    FramePong,
		Payload: cp,
	}
}
