// Package session — session manager for multiple concurrent sessions.
// The Manager tracks active sessions, handles incoming connections,
// and enforces per-client policies.
package session

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/obfuscation"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

// UserPolicy defines runtime settings for a specific user UUID.
type UserPolicy struct {
	UUID           [16]byte
	Email          string
	Mode           intelligence.Mode
	ObfsConfig     obfuscation.Config
	MaxConnections int
	BandwidthLimit int64
	ExpireAtUnix   int64
	BytesIn        uint64
	BytesOut       uint64
	Enabled        bool
}

// Manager manages a pool of active HiVoid sessions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[ID]*Session
	logger   *zap.Logger

	// Defaults applied to new sessions
	mode     intelligence.Mode
	obfsCfg  obfuscation.Config
	isClient bool

	// uuid is sent in ClientHello on outbound (client) connections.
	uuid [16]byte
	// clientMode and clientObfs are sent in ClientHello on outbound connections.
	clientMode uint8
	clientObfs uint8
	// allowedUUIDs is the server-side allowlist (empty = allow all).
	allowedUUIDs [][16]byte
	// userPolicies are applied after handshake based on client UUID.
	userPolicies map[[16]byte]UserPolicy
}

// NewManager creates a Manager.
func NewManager(isClient bool, mode intelligence.Mode, logger *zap.Logger) *Manager {
	return &Manager{
		sessions: make(map[ID]*Session),
		logger:   logger,
		mode:     mode,
		obfsCfg:  obfuscation.DefaultConfig(),
		isClient: isClient,
	}
}

// AcceptAndHandshake wraps a newly accepted QUIC connection into a Session,
// performs the server-side handshake, and registers it.
func (m *Manager) AcceptAndHandshake(ctx context.Context, conn quic.Connection) (*Session, error) {
	m.mu.RLock()
	cfg := DefaultConfig(m.isClient)
	cfg.Engine = intelligence.NewEngine(m.mode)
	cfg.ObfsConfig = m.obfsCfg
	cfg.AllowedUUIDs = m.allowedUUIDs
	policies := make(map[[16]byte]UserPolicy, len(m.userPolicies))
	for k, v := range m.userPolicies {
		policies[k] = v
	}
	m.mu.RUnlock()

	s, err := New(conn, cfg)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	if err := s.PerformHandshakeAsServer(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("server handshake: %w", err)
	}

	if p, ok := policies[s.ClientUUID()]; ok && p.Enabled {
		// Enforce policy: client must request the settings defined by the admin
		requestedMode, requestedObfs := s.ClientRequestedPolicy()
		if uint8(p.Mode) != requestedMode || ObfsNameToID(ObfsConfigToName(p.ObfsConfig)) != requestedObfs {
			id := s.ClientUUID()
			m.logger.Warn("policy mismatch: rejecting session",
				zap.String("uuid", hex.EncodeToString(id[:])),
				zap.Uint8("req_mode", requestedMode),
				zap.Uint8("policy_mode", uint8(p.Mode)),
				zap.Uint8("req_obfs", requestedObfs),
				zap.Uint8("policy_obfs", ObfsNameToID(ObfsConfigToName(p.ObfsConfig))),
			)
			_ = s.conn.CloseWithError(1, "policy mismatch")
			return nil, fmt.Errorf("requested policy does not match user configuration")
		}
		s.ApplyRuntime(p.Mode, p.ObfsConfig)
	}

	m.register(s)
	s.StartControlLoop()
	s.StartRekeyScheduler()
	s.engine.Start()

	m.logger.Info("session established",
		zap.String("id", s.id.String()),
		zap.String("remote", conn.RemoteAddr().String()),
	)
	return s, nil
}

// Dial creates a new client-side session over an established QUIC connection.
func (m *Manager) Dial(ctx context.Context, conn quic.Connection) (*Session, error) {
	cfg := DefaultConfig(m.isClient)
	cfg.Engine = intelligence.NewEngine(m.mode)
	cfg.ObfsConfig = m.obfsCfg
	m.mu.RLock()
	cfg.UUID = m.uuid
	cfg.ClientMode = m.clientMode
	cfg.ClientObfs = m.clientObfs
	m.mu.RUnlock()

	s, err := New(conn, cfg)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	if err := s.PerformHandshakeAsClient(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("client handshake: %w", err)
	}

	m.register(s)
	s.StartControlLoop()
	s.StartRekeyScheduler()
	s.engine.Start()

	m.logger.Info("session dialed",
		zap.String("id", s.id.String()),
		zap.String("remote", conn.RemoteAddr().String()),
	)
	return s, nil
}

// Get retrieves a session by ID.
func (m *Manager) Get(id ID) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// Remove closes and removes a session.
func (m *Manager) Remove(id ID) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()

	if ok {
		_ = s.Close()
		m.logger.Info("session removed", zap.String("id", id.String()))
	}
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// CloseAll shuts down all managed sessions.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	ids := make([]ID, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	for _, id := range ids {
		m.Remove(id)
	}
}

// SetObfuscation applies a new obfuscation config to all future sessions.
func (m *Manager) SetObfuscation(cfg obfuscation.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.obfsCfg = cfg
}

// SetMode updates the default runtime mode for future sessions.
func (m *Manager) SetMode(mode intelligence.Mode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mode = mode
}

// SetClientUUID sets the UUID that will be sent in ClientHello for outbound
// (client-side) connections. Must be called before Connect/Dial.
func (m *Manager) SetClientUUID(u [16]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uuid = u
}

// SetClientParams configures the mode and obfs sent during outbound handshake.
func (m *Manager) SetClientParams(mode intelligence.Mode, obfsName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clientMode = uint8(mode)
	m.clientObfs = ObfsNameToID(obfsName)
}

// SetAllowedUUIDs configures the server-side UUID allowlist.
// Connections from clients whose UUID is not in the list will be rejected.
// Pass nil or an empty slice to allow all clients.
func (m *Manager) SetAllowedUUIDs(uuids [][16]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowedUUIDs = uuids
}

// SetUserPolicies atomically replaces user policies.
func (m *Manager) SetUserPolicies(policies map[[16]byte]UserPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[[16]byte]UserPolicy, len(policies))
	for k, v := range policies {
		cp[k] = v
	}
	m.userPolicies = cp
}

// RefreshActiveSessionPolicies reapplies user policy mode/obfs to active sessions.
func (m *Manager) RefreshActiveSessionPolicies() {
	m.mu.RLock()
	policies := make(map[[16]byte]UserPolicy, len(m.userPolicies))
	for k, v := range m.userPolicies {
		policies[k] = v
	}
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	defaultMode := m.mode
	defaultObfs := m.obfsCfg
	m.mu.RUnlock()

	for _, s := range sessions {
		if p, ok := policies[s.ClientUUID()]; ok && p.Enabled {
			s.ApplyRuntime(p.Mode, p.ObfsConfig)
			continue
		}
		s.ApplyRuntime(defaultMode, defaultObfs)
	}
}

// ObfsConfigForName maps a config string to concrete obfuscation parameters.
func ObfsConfigForName(name string) obfuscation.Config {
	cfg := obfuscation.DefaultConfig()
	switch toLowerASCII(name) {
	case "", "none":
		cfg.Enabled = false
	case "random":
		cfg.Enabled = true
	case "http":
		cfg.Enabled = true
		cfg.PaddingPct = 0.5
		cfg.MaxPaddingBytes = 384
		cfg.MaxJitterMs = 10
		cfg.BurstBytesMax = 48 * 1024
	case "tls":
		cfg.Enabled = true
		cfg.PaddingPct = 0.7
		cfg.MaxPaddingBytes = 512
		cfg.MaxJitterMs = 15
		cfg.BurstBytesMax = 40 * 1024
	default:
		cfg.Enabled = false
	}
	return cfg
}

// ObfsConfigToName maps an obfuscation config back to its name.
func ObfsConfigToName(cfg obfuscation.Config) string {
	if !cfg.Enabled {
		return "none"
	}
	if cfg.PaddingPct == 0.5 && cfg.MaxPaddingBytes == 384 {
		return "http"
	}
	if cfg.PaddingPct == 0.7 && cfg.MaxPaddingBytes == 512 {
		return "tls"
	}
	return "random"
}

// ObfsNameToID converts an obfuscation config string to its wire ID for ClientHello.
func ObfsNameToID(name string) uint8 {
	switch toLowerASCII(name) {
	case "random":
		return 1
	case "http":
		return 2
	case "tls":
		return 3
	default:
		return 0 // "none" or empty
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

func (m *Manager) register(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.id] = s
}
