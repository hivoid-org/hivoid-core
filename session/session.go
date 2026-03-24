// Package session implements the HiVoid session layer.
//
// A Session ties together:
//   - A QUIC connection
//   - Hybrid key exchange state
//   - Per-direction AEAD ciphers
//   - Frame read/write with nonce tracking
//   - Key rotation (rekey) scheduling
//   - Proxy tunnel dial/accept for system traffic forwarding
package session

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	hvcrypto "github.com/hivoid-org/hivoid-core/crypto"
	"github.com/hivoid-org/hivoid-core/frames"
	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/obfuscation"
	"github.com/quic-go/quic-go"
)

// ID is a 16-byte random session identifier.
type ID [16]byte

func (id ID) String() string { return hex.EncodeToString(id[:]) }

// GenerateID creates a new random session ID.
func GenerateID() (ID, error) {
	var id ID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, fmt.Errorf("generate session id: %w", err)
	}
	return id, nil
}

// State tracks the session lifecycle state.
type State uint8

const (
	StateHandshaking State = iota
	StateActive
	StateRekeying
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateHandshaking:
		return "HANDSHAKING"
	case StateActive:
		return "ACTIVE"
	case StateRekeying:
		return "REKEYING"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// Session is a fully authenticated HiVoid session over a single QUIC connection.
type Session struct {
	id       ID
	conn     quic.Connection
	isClient bool

	// uuid is the client's identity, sent in ClientHello.
	// On the client side it is set from Config.UUID before the handshake.
	// On the server side it is populated from the received ClientHello.
	uuid [16]byte

	// clientUUID holds the UUID extracted from the peer's ClientHello
	// (server-side only, available after PerformHandshakeAsServer returns).
	clientUUID [16]byte

	// allowedUUIDs is the server-side allowlist (empty = allow all).
	allowedUUIDs map[[16]byte]struct{}

	// State machine
	mu    sync.RWMutex
	state State

	// salt is the shared session salt exchanged in ClientHello.
	// It is known by both client and server and used as AEAD AAD so that
	// every encrypted record is bound to this specific session.
	// BUG FIX: previously s.id[:] was used as AAD, but each side generates
	// distinct random IDs, causing AAD mismatch and decryption failures.
	salt []byte

	// Current AEAD ciphers (replaced atomically during rekey).
	// RWMutex allows concurrent tunnel Seal/Open (RLock) while
	// serializing control-stream nonce increments and rekey (Lock).
	encryptMu   sync.RWMutex
	encryptor   *hvcrypto.AEAD
	sendNonce   []byte
	sendCounter atomic.Uint64

	decryptMu   sync.RWMutex
	decryptor   *hvcrypto.AEAD
	recvNonce   []byte
	recvCounter atomic.Uint64

	// Key rotation
	rekeySeq   uint32
	rekeyAt    time.Time
	rekeyBytes int64
	sentBytes  atomic.Int64

	// Control stream (stream 0): carries non-data frames
	ctrlStream quic.Stream

	// Intelligence and obfuscation
	engine *intelligence.Engine
	obfs   *obfuscation.Obfuscator

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	// Derived keys (kept for rekey chaining)
	currentKeys *hvcrypto.DerivedKeys

	// Traffic monitoring (session-lifetime counters)
	TrafficSent atomic.Uint64
	TrafficRecv atomic.Uint64

	// Requested policy from client (ClientHello)
	requestedMode uint8
	requestedObfs uint8
}

// Config holds session configuration options.
type Config struct {
	RekeyInterval time.Duration
	RekeyBytes    int64
	IsClient      bool
	Engine        *intelligence.Engine
	ObfsConfig    obfuscation.Config

	// UUID is the 16-byte client identity sent in ClientHello (client side only).
	// Leave zero to send an anonymous connection.
	UUID [16]byte

	// AllowedUUIDs is the server-side allowlist. If non-empty, clients whose
	// UUID is not in the list are rejected during handshake.
	AllowedUUIDs [][16]byte

	// ClientMode is the mode the client wants to use (client side only).
	ClientMode uint8
	// ClientObfs is the obfuscation type the client wants to use (client side only).
	ClientObfs uint8
}

// DefaultConfig returns production-ready session defaults.
func DefaultConfig(isClient bool) Config {
	return Config{
		RekeyInterval: 10 * time.Minute,
		RekeyBytes:    100 * 1024 * 1024, // 100 MB
		IsClient:      isClient,
		Engine:        intelligence.NewEngine(intelligence.ModeAdaptive),
		ObfsConfig:    obfuscation.DefaultConfig(),
	}
}

// New creates a Session that wraps an already-established QUIC connection.
// The hybrid key exchange (ClientHello/ServerHello) must be performed
// via PerformHandshake before this session is usable.
func New(conn quic.Connection, cfg Config) (*Session, error) {
	id, err := GenerateID()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Session{
		id:         id,
		conn:       conn,
		isClient:   cfg.IsClient,
		uuid:       cfg.UUID,
		state:      StateHandshaking,
		rekeyAt:    time.Now().Add(cfg.RekeyInterval),
		rekeyBytes: cfg.RekeyBytes,
		engine:     cfg.Engine,
		obfs:          obfuscation.New(cfg.ObfsConfig),
		ctx:           ctx,
		cancel:        cancel,
		done:          make(chan struct{}),
		requestedMode: cfg.ClientMode,
		requestedObfs: cfg.ClientObfs,
	}

	// Build UUID allowlist map for O(1) lookups on the server side.
	if len(cfg.AllowedUUIDs) > 0 {
		s.allowedUUIDs = make(map[[16]byte]struct{}, len(cfg.AllowedUUIDs))
		for _, u := range cfg.AllowedUUIDs {
			s.allowedUUIDs[u] = struct{}{}
		}
	}

	return s, nil
}

// ID returns the session identifier.
func (s *Session) ID() ID { return s.id }

// State returns the current session state.
func (s *Session) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// Connection returns the underlying QUIC connection.
func (s *Session) Connection() quic.Connection { return s.conn }

// GetTrafficStats returns the total bytes sent and received during this session.
func (s *Session) GetTrafficStats() (uint64, uint64) {
	return s.TrafficSent.Load(), s.TrafficRecv.Load()
}

// PerformHandshakeAsClient executes the client-side hybrid key exchange.
// Must be called immediately after QUIC connection is established.
func (s *Session) PerformHandshakeAsClient() error {
	// Open the control stream (stream 0)
	ctrlStream, err := s.conn.OpenStreamSync(s.ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	s.ctrlStream = ctrlStream

	// Generate hybrid keypair for this session
	priv, pub, err := hvcrypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate hybrid keypair: %w", err)
	}

	// Generate session salt (mixed into HKDF and used as AEAD AAD)
	salt, err := hvcrypto.RandomBytes(32)
	if err != nil {
		return fmt.Errorf("generate session salt: %w", err)
	}
	s.salt = salt // store shared salt for AEAD AAD

	// --- Send ClientHello ---
	hello := &frames.ClientHello{Version: 1}
	copy(hello.SessionSalt[:], salt)
	copy(hello.X25519PublicKey[:], pub.X25519Public)
	copy(hello.MLKEMEncapKey[:], pub.MLKEMEncapKey)
	hello.UUID = s.uuid // client identity (may be zero for anonymous)
	hello.Mode = s.requestedMode
	hello.Obfs = s.requestedObfs

	helloFrame := frames.NewControlFrame(hello.Encode())
	if _, err := helloFrame.WriteTo(ctrlStream); err != nil {
		return fmt.Errorf("send client hello: %w", err)
	}

	// --- Receive ServerHello ---
	respFrame, err := frames.Decode(ctrlStream)
	if err != nil {
		return fmt.Errorf("recv server hello frame: %w", err)
	}
	serverHello, err := frames.DecodeServerHello(respFrame.Payload)
	if err != nil {
		return fmt.Errorf("decode server hello: %w", err)
	}

	// --- Decapsulate shared secret ---
	sharedSecret, err := hvcrypto.Decapsulate(priv, serverHello.X25519PublicKey[:], serverHello.MLKEMCiphertext[:])
	if err != nil {
		return fmt.Errorf("decapsulate: %w", err)
	}

	// --- Derive session keys ---
	dk, err := hvcrypto.DeriveSessionKeys(sharedSecret, salt, true)
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}

	if err := s.installKeys(dk); err != nil {
		return fmt.Errorf("install keys: %w", err)
	}

	s.mu.Lock()
	s.state = StateActive
	s.mu.Unlock()

	return nil
}

// PerformHandshakeAsServer executes the server-side hybrid key exchange.
// Must be called after accepting a QUIC connection and opening stream 0.
func (s *Session) PerformHandshakeAsServer() error {
	// Accept the control stream from the client
	ctrlStream, err := s.conn.AcceptStream(s.ctx)
	if err != nil {
		return fmt.Errorf("accept control stream: %w", err)
	}
	s.ctrlStream = ctrlStream

	// --- Receive ClientHello ---
	helloFrame, err := frames.Decode(ctrlStream)
	if err != nil {
		return fmt.Errorf("recv client hello frame: %w", err)
	}
	clientHello, err := frames.DecodeClientHello(helloFrame.Payload)
	if err != nil {
		return fmt.Errorf("decode client hello: %w", err)
	}

	// Store the shared salt for AEAD AAD — both sides now use the same value.
	s.salt = make([]byte, 32)
	copy(s.salt, clientHello.SessionSalt[:])

	// Record the client's UUID and enforce the allowlist if configured.
	s.clientUUID = clientHello.UUID
	s.requestedMode = clientHello.Mode
	s.requestedObfs = clientHello.Obfs

	if len(s.allowedUUIDs) > 0 {
		if _, ok := s.allowedUUIDs[s.clientUUID]; !ok {
			_ = s.conn.CloseWithError(1, "unauthorized uuid")
			return fmt.Errorf("client uuid not in allowlist")
		}
	}

	// --- Encapsulate shared secret ---
	clientPub := &hvcrypto.HybridPublicKey{
		X25519Public:  clientHello.X25519PublicKey[:],
		MLKEMEncapKey: clientHello.MLKEMEncapKey[:],
	}

	serverX25519Pub, mlkemCT, sharedSecret, err := hvcrypto.Encapsulate(clientPub)
	if err != nil {
		return fmt.Errorf("encapsulate: %w", err)
	}

	// --- Send ServerHello ---
	sh := &frames.ServerHello{Version: clientHello.Version}
	copy(sh.X25519PublicKey[:], serverX25519Pub)
	copy(sh.MLKEMCiphertext[:], mlkemCT)

	shFrame := frames.NewControlFrame(sh.Encode())
	if _, err := shFrame.WriteTo(ctrlStream); err != nil {
		return fmt.Errorf("send server hello: %w", err)
	}

	// --- Derive session keys (using client's salt) ---
	dk, err := hvcrypto.DeriveSessionKeys(sharedSecret, clientHello.SessionSalt[:], false)
	if err != nil {
		return fmt.Errorf("derive session keys: %w", err)
	}

	if err := s.installKeys(dk); err != nil {
		return fmt.Errorf("install keys: %w", err)
	}

	s.mu.Lock()
	s.state = StateActive
	s.mu.Unlock()

	return nil
}

// installKeys sets up the AEAD encryptor and decryptor from DerivedKeys.
func (s *Session) installKeys(dk *hvcrypto.DerivedKeys) error {
	enc, err := hvcrypto.NewAEADWithSuite(dk.Suite, dk.EncryptKey)
	if err != nil {
		return fmt.Errorf("build encryptor: %w", err)
	}
	dec, err := hvcrypto.NewAEADWithSuite(dk.Suite, dk.DecryptKey)
	if err != nil {
		return fmt.Errorf("build decryptor: %w", err)
	}

	s.encryptMu.Lock()
	s.encryptor = enc
	s.sendNonce = make([]byte, enc.NonceSize())
	copy(s.sendNonce, dk.SendNonce)
	s.encryptMu.Unlock()

	s.decryptMu.Lock()
	s.decryptor = dec
	s.recvNonce = make([]byte, dec.NonceSize())
	copy(s.recvNonce, dk.RecvNonce)
	s.decryptMu.Unlock()

	// Keep reference for rekey chaining
	if s.currentKeys != nil {
		hvcrypto.ZeroizeDerivedKeys(s.currentKeys)
	}
	s.currentKeys = dk
	return nil
}

// SendStream opens a new QUIC data stream and writes encrypted payload to it.
// Returns after the full payload has been sent.
func (s *Session) SendStream(ctx context.Context, data []byte) error {
	if s.State() != StateActive {
		return fmt.Errorf("session not active (state=%s)", s.State())
	}

	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open data stream: %w", err)
	}
	defer stream.Close()

	encrypted, nonce, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	// Encode: nonce (12B) || ciphertext
	payload := make([]byte, len(nonce)+len(encrypted))
	copy(payload, nonce)
	copy(payload[len(nonce):], encrypted)

	f := frames.NewDataFrame(payload, true)

	// Apply obfuscation
	f, err = s.obfs.Wrap(f)
	if err != nil {
		return fmt.Errorf("obfuscate frame: %w", err)
	}

	s.obfs.ApplyJitter()
	s.obfs.CheckBurst(int64(len(f.Payload)))

	if _, err := f.WriteTo(stream); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}

	s.TrafficSent.Add(uint64(len(data)))
	sent := s.sentBytes.Add(int64(len(data)))
	// Check if rekey is needed by volume (only client initiates rekey)
	if s.isClient && sent > s.rekeyBytes {
		go s.TriggerRekey() //nolint:errcheck
		s.sentBytes.Store(0)
	}

	return nil
}

// RecvStream accepts the next inbound QUIC data stream and returns its decrypted payload.
// NOTE: this method only handles FrameData streams. For proxy tunnel streams,
// use AcceptTunnel instead. In a mixed server, always accept via a dispatcher.
func (s *Session) RecvStream(ctx context.Context) ([]byte, error) {
	stream, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept stream: %w", err)
	}
	defer stream.Close()

	f, err := frames.Decode(stream)
	if err != nil {
		return nil, fmt.Errorf("decode frame: %w", err)
	}

	// Strip obfuscation padding if present
	f, err = s.obfs.Unwrap(f)
	if err != nil {
		return nil, fmt.Errorf("deobfuscate: %w", err)
	}

	if f.Type != frames.FrameData {
		return nil, fmt.Errorf("expected DATA frame, got 0x%02x", f.Type)
	}

	// Decode: nonce (12B) || ciphertext
	if len(f.Payload) < 12 {
		return nil, fmt.Errorf("data frame payload too short")
	}
	nonce := f.Payload[:12]
	ciphertext := f.Payload[12:]

	plain, err := s.decrypt(ciphertext, nonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	s.TrafficRecv.Add(uint64(len(plain)))
	return plain, nil
}

// --- Tunnel (Proxy) API ---

// DialTunnel opens a new multiplexed proxy tunnel to the given target address ("host:port").
// The returned net.Conn carries application-layer AEAD encryption over the QUIC stream.
// Used by the SOCKS5/HTTP proxy on the client side.
func (s *Session) DialTunnel(ctx context.Context, target string) (net.Conn, error) {
	if s.State() != StateActive {
		return nil, fmt.Errorf("session not active")
	}

	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open tunnel stream: %w", err)
	}

	// Send proxy request as the first frame on the stream
	req, err := frames.NewProxyRequest(target)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		return nil, fmt.Errorf("build proxy request: %w", err)
	}
	reqFrame := &frames.Frame{Type: frames.FrameProxy, Payload: req.Encode()}
	if _, err := reqFrame.WriteTo(stream); err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		return nil, fmt.Errorf("send proxy request: %w", err)
	}

	// Wait for proxy response
	respFrame, err := frames.Decode(stream)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		return nil, fmt.Errorf("read proxy response: %w", err)
	}
	resp, err := frames.DecodeProxyResponse(respFrame.Payload)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		return nil, fmt.Errorf("parse proxy response: %w", err)
	}
	if !resp.Success {
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		return nil, fmt.Errorf("proxy connect failed: %s", resp.ErrMsg)
	}

	return newTunnelConn(stream, s, target), nil
}

// AcceptTunnel accepts the next inbound proxy tunnel stream and reads its
// ProxyRequest to discover the target address. Returns the raw QUIC stream and
// target so the caller can:
//  1. Dial the TCP target
//  2. Call session.SendProxyOkToStream(stream) or SendProxyErrToStream(stream, msg)
//  3. Call s.WrapTunnel(stream, target) to get a net.Conn for data relay
//
// This two-phase API lets the forwarder decide success/failure before
// unblocking the client (which waits for the ProxyResponse in DialTunnel).
func (s *Session) AcceptTunnel(ctx context.Context) (quic.Stream, string, error) {
	stream, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("accept tunnel stream: %w", err)
	}

	// Read the first frame: must be FrameProxy (ProxyRequest)
	f, err := frames.Decode(stream)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		return nil, "", fmt.Errorf("read tunnel frame: %w", err)
	}

	if f.Type != frames.FrameProxy {
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		return nil, "", fmt.Errorf("expected PROXY frame, got 0x%02x", f.Type)
	}

	req, err := frames.DecodeProxyRequest(f.Payload)
	if err != nil {
		sendProxyError(stream, err.Error())
		stream.CancelRead(quic.StreamErrorCode(0))
		stream.Close()
		return nil, "", fmt.Errorf("parse proxy request: %w", err)
	}

	return stream, req.Target(), nil
}

// WrapTunnel wraps a pre-negotiated QUIC stream (after the ProxyResponse has
// already been sent) into a net.Conn with AEAD encryption.
func (s *Session) WrapTunnel(stream quic.Stream, target string) net.Conn {
	return newTunnelConn(stream, s, target)
}

// SendProxyOK writes a successful proxy response to the stream.
// Called by the server forwarder after successfully connecting to the target.
func SendProxyOK(stream quic.Stream) error {
	resp := frames.ProxyResponse{Success: true}
	f := &frames.Frame{Type: frames.FrameProxy, Payload: resp.Encode()}
	_, err := f.WriteTo(stream)
	return err
}

// sendProxyError writes a failure proxy response to the stream.
func sendProxyError(stream quic.Stream, msg string) {
	resp := frames.ProxyResponse{Success: false, ErrMsg: msg}
	f := &frames.Frame{Type: frames.FrameProxy, Payload: resp.Encode()}
	_, _ = f.WriteTo(stream)
}

// encrypt uses the session's outbound cipher with the shared salt as AEAD AAD.
// Returns (ciphertext, nonce, error).
func (s *Session) encrypt(plaintext []byte) ([]byte, []byte, error) {
	s.encryptMu.Lock()
	defer s.encryptMu.Unlock()

	// Make a copy of the current nonce for this record
	nonceCopy := make([]byte, len(s.sendNonce))
	copy(nonceCopy, s.sendNonce)

	// Increment nonce for next record
	hvcrypto.IncrementNonce(s.sendNonce)

	// Use the shared session salt as AAD.
	// Both client and server know the salt from the ClientHello exchange,
	// so this value matches on both sides (unlike the local session ID).
	ct, err := s.encryptor.Seal(nonceCopy, plaintext, s.salt)
	if err != nil {
		return nil, nil, err
	}
	return ct, nonceCopy, nil
}

// decrypt uses the session's inbound cipher with the shared salt as AAD.
func (s *Session) decrypt(ciphertext, nonce []byte) ([]byte, error) {
	s.decryptMu.Lock()
	defer s.decryptMu.Unlock()
	return s.decryptor.Open(nonce, ciphertext, s.salt)
}

// EncryptForTunnel encrypts plaintext for use in a tunnel stream.
// Uses a random nonce (suitable for high-volume relay with independent nonce state).
// RLock allows multiple tunnels to encrypt concurrently.
func (s *Session) EncryptForTunnel(plaintext []byte) (nonce, ciphertext []byte, err error) {
	// Generate a random nonce rather than using the incrementing session nonce,
	// so tunnel streams have independent nonce state.
	nonce = make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("tunnel nonce: %w", err)
	}
	s.encryptMu.RLock()
	ct, err := s.encryptor.Seal(nonce, plaintext, s.salt)
	s.encryptMu.RUnlock()
	if err != nil {
		return nil, nil, err
	}
	return nonce, ct, nil
}

// DecryptForTunnel decrypts tunnel stream data.
// RLock allows multiple tunnels to decrypt concurrently.
func (s *Session) DecryptForTunnel(nonce, ciphertext []byte) ([]byte, error) {
	s.decryptMu.RLock()
	defer s.decryptMu.RUnlock()
	return s.decryptor.Open(nonce, ciphertext, s.salt)
}

// Salt returns the shared session salt.
func (s *Session) Salt() []byte {
	return s.salt
}

// ClientUUID returns the UUID the peer sent in ClientHello.
// Only meaningful on the server side after a successful handshake.
func (s *Session) ClientUUID() [16]byte {
	return s.clientUUID
}

// ClientRequestedPolicy returns the mode and obfs ID the client asked for.
func (s *Session) ClientRequestedPolicy() (uint8, uint8) {
	return s.requestedMode, s.requestedObfs
}

// ApplyRuntime updates runtime tunables for this session without reconnecting.
// It is safe to call while the session is active.
func (s *Session) ApplyRuntime(mode intelligence.Mode, obfsCfg obfuscation.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.engine != nil {
		s.engine.SetMode(mode)
	}
	if s.obfs != nil {
		s.obfs.Update(obfsCfg)
	}
}

// SendFrame writes an arbitrary frame to the control stream.
func (s *Session) SendFrame(f *frames.Frame) error {
	if s.ctrlStream == nil {
		return fmt.Errorf("control stream not open")
	}
	_, err := f.WriteTo(s.ctrlStream)
	return err
}

// RecvFrame reads the next frame from the control stream.
func (s *Session) RecvFrame() (*frames.Frame, error) {
	if s.ctrlStream == nil {
		return nil, fmt.Errorf("control stream not open")
	}
	return frames.Decode(s.ctrlStream)
}

// Close tears down the session gracefully.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateClosed {
		return nil
	}
	s.state = StateClosed
	s.cancel()

	hvcrypto.ZeroizeDerivedKeys(s.currentKeys)

	if s.ctrlStream != nil {
		s.ctrlStream.Close()
	}
	return s.conn.CloseWithError(0, "session closed")
}

// addCounterToNonce returns nonce XOR'd with counter (big-endian) for unique per-record nonces.
func addCounterToNonce(base []byte, counter uint64) []byte {
	nonce := make([]byte, len(base))
	copy(nonce, base)
	// XOR the last 8 bytes with the counter
	c := make([]byte, 8)
	binary.BigEndian.PutUint64(c, counter)
	offset := len(nonce) - 8
	for i := 0; i < 8; i++ {
		nonce[offset+i] ^= c[i]
	}
	return nonce
}
