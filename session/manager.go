// Package session — session manager for multiple concurrent sessions.
// The Manager tracks active sessions, handles incoming connections,
// and enforces per-client policies.
package session

import (
	"context"
	"fmt"
	"sync"

	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/obfuscation"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

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
	// allowedUUIDs is the server-side allowlist (empty = allow all).
	allowedUUIDs [][16]byte
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
	cfg := DefaultConfig(m.isClient)
	cfg.Engine = intelligence.NewEngine(m.mode)
	cfg.ObfsConfig = m.obfsCfg
	m.mu.RLock()
	cfg.AllowedUUIDs = m.allowedUUIDs
	m.mu.RUnlock()

	s, err := New(conn, cfg)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	if err := s.PerformHandshakeAsServer(); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("server handshake: %w", err)
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

// SetClientUUID sets the UUID that will be sent in ClientHello for outbound
// (client-side) connections. Must be called before Connect/Dial.
func (m *Manager) SetClientUUID(u [16]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uuid = u
}

// SetAllowedUUIDs configures the server-side UUID allowlist.
// Connections from clients whose UUID is not in the list will be rejected.
// Pass nil or an empty slice to allow all clients.
func (m *Manager) SetAllowedUUIDs(uuids [][16]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowedUUIDs = uuids
}

func (m *Manager) register(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.id] = s
}
