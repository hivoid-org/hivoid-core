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
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

var (
	ErrHandshakeTimeout = errors.New("handshake timeout (probing?)")
	ErrInvalidFrame     = errors.New("invalid protocol frame")
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
	conn     *quic.Conn
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
	ctrlStream *quic.Stream
	ctrlReader *bufio.Reader

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

	// Ghost CBR engine (nil unless Ghost obfuscation is active)
	ghost *ghostEngine
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
func New(conn *quic.Conn, cfg Config) (*Session, error) {
	id, err := GenerateID()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Session{
		id:            id,
		conn:          conn,
		isClient:      cfg.IsClient,
		uuid:          cfg.UUID,
		state:         StateHandshaking,
		rekeyAt:       time.Now().Add(cfg.RekeyInterval),
		rekeyBytes:    cfg.RekeyBytes,
		engine:        cfg.Engine,
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
func (s *Session) Connection() *quic.Conn { return s.conn }

// GetTrafficStats returns the total bytes sent and received during this session.
func (s *Session) GetTrafficStats() (uint64, uint64) {
	return s.TrafficSent.Load(), s.TrafficRecv.Load()
}

// PerformHandshakeAsClient executes the client-side hybrid key exchange.
func (s *Session) PerformHandshakeAsClient(ctx context.Context) error {
	ctrlStream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	s.ctrlStream = ctrlStream
	s.ctrlReader = bufio.NewReader(ctrlStream)

	// Set a deadline for the entire handshake process on this stream
	if deadline, ok := ctx.Deadline(); ok {
		_ = ctrlStream.SetDeadline(deadline)
	}
	defer ctrlStream.SetDeadline(time.Time{})

	// --- H3/MASQUE/WebTransport Protocol Wrapper ---
	if s.requestedObfs == 4 || s.requestedObfs == 5 {
		// 1. Send H3 Settings
		if _, err := ctrlStream.Write(frames.EncodeH3Settings()); err != nil {
			return fmt.Errorf("h3 settings: %w", err)
		}
		// 2. Send CONNECT request
		if s.requestedObfs == 4 {
			if _, err := ctrlStream.Write(frames.EncodeMasqueRequest("hivoid-server")); err != nil {
				return fmt.Errorf("masque request: %w", err)
			}
		} else {
			if _, err := ctrlStream.Write(frames.EncodeWebTransportRequest("hivoid-server")); err != nil {
				return fmt.Errorf("webtransport request: %w", err)
			}
		}
		// 3. Receive/Skip Server H3 response
		if err := frames.DiscardH3Frame(s.ctrlReader); err != nil {
			return fmt.Errorf("h3 settings response: %w", err)
		}
		if err := frames.DiscardH3Frame(s.ctrlReader); err != nil {
			return fmt.Errorf("h3 headers response: %w", err)
		}
	}

	priv, pub, err := hvcrypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate hybrid keypair: %w", err)
	}

	salt, err := hvcrypto.RandomBytes(32)
	if err != nil {
		return fmt.Errorf("generate session salt: %w", err)
	}
	s.salt = salt

	hello := &frames.ClientHello{Version: 1}
	copy(hello.SessionSalt[:], salt)
	copy(hello.X25519PublicKey[:], pub.X25519Public)
	copy(hello.MLKEMEncapKey[:], pub.MLKEMEncapKey)
	hello.UUID = s.uuid
	hello.Mode = s.requestedMode
	hello.Obfs = s.requestedObfs

	helloFrame := frames.NewControlFrame(hello.Encode())
	if _, err := helloFrame.WriteTo(ctrlStream); err != nil {
		return fmt.Errorf("send client hello: %w", err)
	}

	helloFrame, err = frames.Decode(s.ctrlReader)
	if err != nil {
		return fmt.Errorf("recv server hello frame: %w", err)
	}
	serverHello, err := frames.DecodeServerHello(helloFrame.Payload)
	if err != nil {
		return fmt.Errorf("decode server hello: %w", err)
	}

	sharedSecret, err := hvcrypto.Decapsulate(priv, serverHello.X25519PublicKey[:], serverHello.MLKEMCiphertext[:])
	if err != nil {
		return fmt.Errorf("decapsulate: %w", err)
	}

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

	// Start Ghost CBR engine if requested
	if s.requestedObfs == 6 {
		s.ghost = newGhostEngine(s)
		go s.ghost.Run()
	}

	return nil
}

// PerformHandshakeAsServer executes the server-side hybrid key exchange.
func (s *Session) PerformHandshakeAsServer(ctx context.Context) error {
	ctrlStream, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept control stream: %w", err)
	}
	s.ctrlStream = ctrlStream
	s.ctrlReader = bufio.NewReader(ctrlStream)

	// Set a deadline for the entire handshake process on this stream
	if deadline, ok := ctx.Deadline(); ok {
		_ = ctrlStream.SetDeadline(deadline)
	}
	defer ctrlStream.SetDeadline(time.Time{})

	// Peeking at the first byte of control stream to detect H3 framing.
	// Standard HiVoid starts with 0x02 (FrameControl).
	// H3 starts with 0x04 (H3FrameSettings).
	first, _ := s.ctrlReader.Peek(1)
	if len(first) > 0 && first[0] == byte(frames.H3FrameSettings) {
		// 1. Consume H3 Settings and Request (CONNECT / WebTransport)
		if err := frames.DiscardH3Frame(s.ctrlReader); err != nil {
			return fmt.Errorf("read client h3 settings: %w", err)
		}
		if err := frames.DiscardH3Frame(s.ctrlReader); err != nil {
			return fmt.Errorf("read client h3 headers: %w", err)
		}
		// 2. Send H3 Response (Settings + 200 OK)
		if _, err := ctrlStream.Write(frames.EncodeH3Settings()); err != nil {
			return fmt.Errorf("h3 settings server response: %w", err)
		}
		if _, err := ctrlStream.Write(frames.EncodeMasqueResponse()); err != nil {
			return fmt.Errorf("h3 headers server response: %w", err)
		}
	}

	// Read ClientHello with another tight timeout to fail probes fast
	firstFrameChan := make(chan struct {
		f   *frames.Frame
		err error
	}, 1)

	go func() {
		f, err := frames.Decode(s.ctrlReader)
		firstFrameChan <- struct {
			f   *frames.Frame
			err error
		}{f, err}
	}()

	var helloFrame *frames.Frame
	select {
	case res := <-firstFrameChan:
		helloFrame, err = res.f, res.err
	case <-time.After(5 * time.Second):
		return ErrHandshakeTimeout
	}

	if err != nil {
		return fmt.Errorf("read client hello: %w", err)
	}

	if helloFrame.Type != frames.FrameControl {
		return fmt.Errorf("expected CONTROL frame, got 0x%02x: %w", helloFrame.Type, ErrInvalidFrame)
	}

	clientHello, err := frames.DecodeClientHello(helloFrame.Payload)
	if err != nil {
		return fmt.Errorf("decode client hello: %w", err)
	}

	s.salt = make([]byte, 32)
	copy(s.salt, clientHello.SessionSalt[:])

	s.clientUUID = clientHello.UUID
	s.requestedMode = clientHello.Mode
	s.requestedObfs = clientHello.Obfs

	if len(s.allowedUUIDs) > 0 {
		if _, ok := s.allowedUUIDs[s.clientUUID]; !ok {
			_ = s.conn.CloseWithError(1, "unauthorized uuid")
			return fmt.Errorf("client uuid not in allowlist")
		}
	}

	clientPub := &hvcrypto.HybridPublicKey{
		X25519Public:  clientHello.X25519PublicKey[:],
		MLKEMEncapKey: clientHello.MLKEMEncapKey[:],
	}

	serverX25519Pub, mlkemCT, sharedSecret, err := hvcrypto.Encapsulate(clientPub)
	if err != nil {
		return fmt.Errorf("encapsulate: %w", err)
	}

	sh := &frames.ServerHello{Version: clientHello.Version}
	copy(sh.X25519PublicKey[:], serverX25519Pub)
	copy(sh.MLKEMCiphertext[:], mlkemCT)

	shFrame := frames.NewControlFrame(sh.Encode())
	if _, err := shFrame.WriteTo(ctrlStream); err != nil {
		return fmt.Errorf("send server hello: %w", err)
	}

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

	// Start Ghost CBR engine if client requested it
	if s.requestedObfs == 6 {
		s.ghost = newGhostEngine(s)
		go s.ghost.Run()
	}

	return nil
}

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

	if s.currentKeys != nil {
		hvcrypto.ZeroizeDerivedKeys(s.currentKeys)
	}
	s.currentKeys = dk
	return nil
}

// SendStream opens a new QUIC data stream and writes encrypted payload to it.
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

	payload := make([]byte, len(nonce)+len(encrypted))
	copy(payload, nonce)
	copy(payload[len(nonce):], encrypted)

	f := frames.NewDataFrame(payload, true)
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
	if s.isClient && sent > s.rekeyBytes {
		go s.TriggerRekey() //nolint:errcheck
		s.sentBytes.Store(0)
	}

	return nil
}

// RecvStream accepts the next inbound QUIC data stream and returns its decrypted payload.
func (s *Session) RecvStream(ctx context.Context) ([]byte, error) {
	for {
		stream, err := s.conn.AcceptStream(ctx)
		if err != nil {
			return nil, fmt.Errorf("accept stream: %w", err)
		}

		f, err := frames.Decode(stream)
		if err != nil {
			_ = stream.Close()
			return nil, fmt.Errorf("decode frame: %w", err)
		}

		// Silently discard Ghost Noise frames
		if f.Type == frames.FrameNoise {
			_ = stream.Close()
			continue
		}

		f, err = s.obfs.Unwrap(f)
		if err != nil {
			_ = stream.Close()
			return nil, fmt.Errorf("deobfuscate: %w", err)
		}

		if f.Type != frames.FrameData {
			_ = stream.Close()
			return nil, fmt.Errorf("expected DATA frame, got 0x%02x", f.Type)
		}

		if len(f.Payload) < 12 {
			_ = stream.Close()
			return nil, fmt.Errorf("data frame payload too short")
		}
		nonce := f.Payload[:12]
		ciphertext := f.Payload[12:]

		plain, err := s.decrypt(ciphertext, nonce)
		if err != nil {
			_ = stream.Close()
			return nil, fmt.Errorf("decrypt: %w", err)
		}

		s.TrafficRecv.Add(uint64(len(plain)))
		_ = stream.Close()
		return plain, nil
	}
}

// DialTunnel opens a new multiplexed proxy tunnel (TCP) to the target address.
func (s *Session) DialTunnel(ctx context.Context, target string) (net.Conn, error) {
	if s.State() != StateActive {
		return nil, fmt.Errorf("session not active")
	}

	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open tunnel stream: %w", err)
	}

	req, err := frames.NewProxyRequest(target)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return nil, fmt.Errorf("build proxy request: %w", err)
	}
	reqFrame := &frames.Frame{Type: frames.FrameProxy, Payload: req.Encode()}
	if _, err := reqFrame.WriteTo(stream); err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return nil, fmt.Errorf("send proxy request: %w", err)
	}

	respFrame, err := frames.Decode(stream)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return nil, fmt.Errorf("read proxy response: %w", err)
	}
	resp, err := frames.DecodeProxyResponse(respFrame.Payload)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return nil, fmt.Errorf("parse proxy response: %w", err)
	}
	if !resp.Success {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return nil, fmt.Errorf("proxy connect failed: %s", resp.ErrMsg)
	}

	return newTunnelConn(stream, s, target), nil
}

// DialUDPTunnel opens a new multiplexed proxy tunnel (UDP) to the target address.
func (s *Session) DialUDPTunnel(ctx context.Context, target string) (net.Conn, error) {
	if s.State() != StateActive {
		return nil, fmt.Errorf("session not active")
	}

	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open tunnel stream: %w", err)
	}

	req, err := frames.NewProxyUDPRequest(target)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return nil, fmt.Errorf("build proxy udp request: %w", err)
	}
	reqFrame := &frames.Frame{Type: frames.FrameProxy, Payload: req.Encode()}
	if _, err := reqFrame.WriteTo(stream); err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return nil, fmt.Errorf("send proxy udp request: %w", err)
	}

	respFrame, err := frames.Decode(stream)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return nil, fmt.Errorf("read proxy response: %w", err)
	}
	resp, err := frames.DecodeProxyResponse(respFrame.Payload)
	if err != nil {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return nil, fmt.Errorf("parse proxy response: %w", err)
	}
	if !resp.Success {
		stream.CancelRead(quic.StreamErrorCode(0))
		_ = stream.Close()
		return nil, fmt.Errorf("proxy connect failed: %s", resp.ErrMsg)
	}

	return newTunnelConn(stream, s, target), nil
}

// AcceptTunnel accepts the next inbound proxy tunnel stream and reads its ProxyRequest.
func (s *Session) AcceptTunnel(ctx context.Context) (*quic.Stream, *frames.ProxyRequest, error) {
	for {
		stream, err := s.conn.AcceptStream(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("accept tunnel stream: %w", err)
		}

		f, err := frames.Decode(stream)
		if err != nil {
			stream.CancelRead(quic.StreamErrorCode(0))
			_ = stream.Close()
			return nil, nil, fmt.Errorf("read tunnel frame: %w", err)
		}

		// Silently discard Ghost Noise frames
		if f.Type == frames.FrameNoise {
			_ = stream.Close()
			continue
		}

		if f.Type != frames.FrameProxy {
			stream.CancelRead(quic.StreamErrorCode(0))
			_ = stream.Close()
			return nil, nil, fmt.Errorf("expected PROXY frame, got 0x%02x", f.Type)
		}

		req, err := frames.DecodeProxyRequest(f.Payload)
		if err != nil {
			_ = sendProxyError(stream, err.Error())
			stream.CancelRead(quic.StreamErrorCode(0))
			_ = stream.Close()
			return nil, nil, fmt.Errorf("parse proxy request: %w", err)
		}

		return stream, req, nil
	}
}

// WrapTunnel wraps a pre-negotiated QUIC stream into a net.Conn with AEAD encryption.
func (s *Session) WrapTunnel(stream *quic.Stream, target string) net.Conn {
	return newTunnelConn(stream, s, target)
}

// SendProxyOK writes a successful proxy response to the stream.
func SendProxyOK(stream *quic.Stream) error {
	resp := frames.ProxyResponse{Success: true}
	f := &frames.Frame{Type: frames.FrameProxy, Payload: resp.Encode()}
	_, err := f.WriteTo(stream)
	return err
}

// SendProxyError writes a failure proxy response to the stream.
func SendProxyError(stream *quic.Stream, msg string) error {
	return sendProxyError(stream, msg)
}

func sendProxyError(stream *quic.Stream, msg string) error {
	resp := frames.ProxyResponse{Success: false, ErrMsg: msg}
	f := &frames.Frame{Type: frames.FrameProxy, Payload: resp.Encode()}
	_, err := f.WriteTo(stream)
	return err
}

func (s *Session) encrypt(plaintext []byte) ([]byte, []byte, error) {
	s.encryptMu.Lock()
	defer s.encryptMu.Unlock()

	nonceCopy := make([]byte, len(s.sendNonce))
	copy(nonceCopy, s.sendNonce)
	hvcrypto.IncrementNonce(s.sendNonce)

	ct, err := s.encryptor.Seal(nonceCopy, plaintext, s.salt)
	if err != nil {
		return nil, nil, err
	}
	return ct, nonceCopy, nil
}

func (s *Session) decrypt(ciphertext, nonce []byte) ([]byte, error) {
	s.decryptMu.Lock()
	defer s.decryptMu.Unlock()
	return s.decryptor.Open(nonce, ciphertext, s.salt)
}

func (s *Session) EncryptForTunnel(plaintext []byte) (nonce, ciphertext []byte, err error) {
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

func (s *Session) DecryptForTunnel(nonce, ciphertext []byte) ([]byte, error) {
	s.decryptMu.RLock()
	defer s.decryptMu.RUnlock()
	return s.decryptor.Open(nonce, ciphertext, s.salt)
}

func (s *Session) Salt() []byte { return s.salt }

func (s *Session) ClientUUID() [16]byte { return s.clientUUID }

func (s *Session) ClientRequestedPolicy() (uint8, uint8) {
	return s.requestedMode, s.requestedObfs
}

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

func (s *Session) SendFrame(f *frames.Frame) error {
	if s.ctrlStream == nil {
		return fmt.Errorf("control stream not open")
	}
	_, err := f.WriteTo(s.ctrlStream)
	return err
}

func (s *Session) RecvFrame() (*frames.Frame, error) {
	if s.ctrlReader == nil {
		return nil, fmt.Errorf("control reader not initialized")
	}
	return frames.Decode(s.ctrlReader)
}

func (s *Session) Close() error {
	if s.ghost != nil {
		s.ghost.Stop()
	}
	s.cancel()
	hvcrypto.ZeroizeDerivedKeys(s.currentKeys)
	if s.ctrlStream != nil {
		_ = s.ctrlStream.Close()
	}
	return s.conn.CloseWithError(0, "session closed")
}

func (s *Session) CloseWithError(code uint64, msg string) error {
	if s.ghost != nil {
		s.ghost.Stop()
	}
	s.cancel()
	hvcrypto.ZeroizeDerivedKeys(s.currentKeys)
	if s.ctrlStream != nil {
		_ = s.ctrlStream.Close()
	}
	return s.conn.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

func addCounterToNonce(base []byte, counter uint64) []byte {
	nonce := make([]byte, len(base))
	copy(nonce, base)
	c := make([]byte, 8)
	binary.BigEndian.PutUint64(c, counter)
	offset := len(nonce) - 8
	for i := 0; i < 8; i++ {
		nonce[offset+i] ^= c[i]
	}
	return nonce
}
