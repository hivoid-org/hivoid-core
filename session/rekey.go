// Package session — key rotation (rekey) logic.
//
// Rekey is triggered either by time (configurable interval) or by
// volume (bytes sent threshold). It derives new keys from the current
// session key material, providing forward secrecy within a session.
//
// IMPORTANT: Only one side (the client) initiates rekey. The server
// only responds to incoming REKEY frames. Both sides must derive from
// the SAME base key material — the initiator's EncryptKey, which is
// the receiver's DecryptKey.
package session

import (
	"fmt"
	"io"
	"time"

	hvcrypto "github.com/hivoid-org/hivoid-core/crypto"
	"github.com/hivoid-org/hivoid-core/frames"
)

// TriggerRekey initiates a key rotation on this session.
// It sends a REKEY frame with a new salt to the peer, derives new keys,
// and installs them. Only the initiating side calls this.
//
// This is safe to call from a goroutine; it serialises on the encryptMu.
func (s *Session) TriggerRekey() error {
	s.mu.Lock()
	if s.state != StateActive {
		s.mu.Unlock()
		return fmt.Errorf("rekey: session not active")
	}
	s.state = StateRekeying
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if s.state == StateRekeying {
			s.state = StateActive
		}
		s.mu.Unlock()
	}()

	// Generate fresh salt for new keys
	newSalt, err := hvcrypto.RandomBytes(32)
	if err != nil {
		return fmt.Errorf("rekey salt: %w", err)
	}

	s.rekeySeq++
	rp := &frames.RekeyPayload{SeqNum: s.rekeySeq}
	copy(rp.NewSalt[:], newSalt)

	// Snapshot the current EncryptKey BEFORE sending (the peer will use
	// its DecryptKey which is identical to our EncryptKey).
	s.encryptMu.Lock()
	currentKey := make([]byte, len(s.currentKeys.EncryptKey))
	copy(currentKey, s.currentKeys.EncryptKey)
	s.encryptMu.Unlock()

	// Send REKEY frame to peer via control stream
	rekeyFrame := frames.NewRekeyFrame(rp.Encode())
	if err := s.SendFrame(rekeyFrame); err != nil {
		return fmt.Errorf("send rekey frame: %w", err)
	}

	// Derive new keys using OUR EncryptKey as base
	newDK, err := hvcrypto.DeriveRekeyMaterial(currentKey, newSalt, s.isClient)
	if err != nil {
		return fmt.Errorf("derive rekey material: %w", err)
	}

	// Install new keys — old keys are automatically zeroized
	if err := s.installKeys(newDK); err != nil {
		return fmt.Errorf("install rekey keys: %w", err)
	}

	// Reset the rekey timer
	s.rekeyAt = time.Now().Add(s.rekeyInterval())
	s.sentBytes.Store(0)

	return nil
}

// HandleRekeyFrame processes an inbound REKEY frame from the peer.
// It derives the same new keys using the provided salt and installs them.
//
// CRITICAL: The receiver must use its DecryptKey as the base material,
// because that corresponds to the sender's EncryptKey (they are swapped
// between client and server). This ensures both sides derive from the
// exact same key material.
func (s *Session) HandleRekeyFrame(f *frames.Frame) error {
	rp, err := frames.DecodeRekeyPayload(f.Payload)
	if err != nil {
		return fmt.Errorf("decode rekey payload: %w", err)
	}

	// Use DecryptKey (= sender's EncryptKey) as the derivation base,
	// so both sides feed the same key material into DeriveRekeyMaterial.
	s.decryptMu.Lock()
	currentKey := make([]byte, len(s.currentKeys.DecryptKey))
	copy(currentKey, s.currentKeys.DecryptKey)
	s.decryptMu.Unlock()

	// Derive new keys — pass !s.isClient because the initiator used
	// its own isClient flag, and we are the opposite side.
	newDK, err := hvcrypto.DeriveRekeyMaterial(currentKey, rp.NewSalt[:], s.isClient)
	if err != nil {
		return fmt.Errorf("derive rekey material (receiver): %w", err)
	}

	if err := s.installKeys(newDK); err != nil {
		return fmt.Errorf("install rekey keys (receiver): %w", err)
	}

	return nil
}

// StartRekeyScheduler starts a background goroutine that triggers rekey on a timer.
// Only the CLIENT side actively triggers rekey events. The server side only
// responds to incoming REKEY frames via the control loop. This prevents
// race conditions where both sides try to rekey simultaneously.
func (s *Session) StartRekeyScheduler() {
	// Server side: do not schedule rekeys, only handle incoming ones.
	if !s.isClient {
		return
	}

	go func() {
		for {
			interval := s.rekeyInterval()
			select {
			case <-time.After(interval):
				if s.State() == StateActive {
					_ = s.TriggerRekey()
				}
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

// StartControlLoop starts a background reader for control-stream frames.
// This is required so incoming REKEY frames are actually applied.
func (s *Session) StartControlLoop() {
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			default:
			}

			f, err := s.RecvFrame()
			if err != nil {
				if err == io.EOF || s.ctx.Err() != nil {
					return
				}
				_ = s.Close()
				return
			}

			switch f.Type {
			case frames.FrameRekey:
				if err := s.HandleRekeyFrame(f); err != nil {
					_ = s.Close()
					return
				}
			default:
				// Ignore unknown control frames for forward compatibility.
			}
		}
	}()
}

// rekeyInterval returns the current rekey interval from engine tuning.
func (s *Session) rekeyInterval() time.Duration {
	if s.engine != nil {
		return s.engine.Tuning().RekeyInterval
	}
	return 10 * time.Minute
}
