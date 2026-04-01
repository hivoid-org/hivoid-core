// Package session — session manager for multiple concurrent sessions.
// The Manager tracks active sessions, handles incoming connections,
// and enforces per-client policies.
package session

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

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
	MaxIPs         int
	BindIP         string
	BandwidthLimit int64
	DataLimit      int64
	ExpireAtUnix   int64
	BytesIn        uint64
	BytesOut       uint64
	Enabled        bool
	BlockedHosts   []string
	BlockedTags    []string
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
	// userIPs tracks unique IPs per user: map[UUID] -> map[IP] -> SessionCount
	userIPs map[[16]byte]map[string]int
}

// NewManager creates a Manager.
func NewManager(isClient bool, mode intelligence.Mode, logger *zap.Logger) *Manager {
	return &Manager{
		sessions: make(map[ID]*Session),
		userIPs:  make(map[[16]byte]map[string]int),
		logger:   logger,
		mode:     mode,
		obfsCfg:  obfuscation.DefaultConfig(),
		isClient: isClient,
	}
}

// AcceptAndHandshake wraps a newly accepted QUIC connection into a Session,
// performs the server-side handshake, and registers it.
func (m *Manager) AcceptAndHandshake(ctx context.Context, conn *quic.Conn) (*Session, error) {
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

	handshakeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := s.PerformHandshakeAsServer(handshakeCtx); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("server handshake: %w", err)
	}

	if p, ok := policies[s.ClientUUID()]; ok {
		if !p.Enabled {
			_ = s.CloseWithError(0x11, "user disabled")
			return nil, fmt.Errorf("user disabled")
		}

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

		// Enforce initial quota check
		now := time.Now().Unix()
		if p.ExpireAtUnix > 0 && now > p.ExpireAtUnix {
			_ = s.CloseWithError(0x10, "account expired")
			return nil, fmt.Errorf("account expired")
		}
		if p.DataLimit > 0 && p.BytesIn+p.BytesOut >= uint64(p.DataLimit) {
			_ = s.CloseWithError(0x10, "data limit reached")
			return nil, fmt.Errorf("data limit reached")
		}

		// Enforce IP limit
		if p.MaxIPs > 0 {
			ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			m.mu.Lock()
			currentIPs := m.userIPs[s.ClientUUID()]
			_, alreadyKnown := currentIPs[ip]
			if !alreadyKnown && len(currentIPs) >= p.MaxIPs {
				m.mu.Unlock()
				clientUUID := s.ClientUUID()
				m.logger.Warn("IP limit reached",
					zap.String("uuid", hex.EncodeToString(clientUUID[:])),
					zap.String("new_ip", ip),
					zap.Int("limit", p.MaxIPs),
				)
				_ = s.CloseWithError(0x11, "IP limit reached")
				return nil, fmt.Errorf("IP limit reached")
			}
			m.mu.Unlock()
		}
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
func (m *Manager) Dial(ctx context.Context, conn *quic.Conn) (*Session, error) {
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

	handshakeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := s.PerformHandshakeAsClient(handshakeCtx); err != nil {
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
		// Update IP tracking
		ip, _, _ := net.SplitHostPort(s.Connection().RemoteAddr().String())
		uuid := s.ClientUUID()
		if m.userIPs[uuid] != nil {
			m.userIPs[uuid][ip]--
			if m.userIPs[uuid][ip] <= 0 {
				delete(m.userIPs[uuid], ip)
				if len(m.userIPs[uuid]) == 0 {
					delete(m.userIPs, uuid)
				}
			}
		}
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

// KickAll closes all active sessions with a signal to the client to reconnect.
// Uses custom error code 0x12 (Reconnect Requested).
func (m *Manager) KickAll() {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()

	m.logger.Info("shock requested: kicking all active sessions", zap.Int("count", len(sessions)))
	for _, s := range sessions {
		// 0x12 is a custom internal app error code for "force reconnect"
		s.CloseWithError(0x12, "reconnect requested by server admin")
	}
}

// SetObfuscation applies a new obfuscation config to all future sessions.
func (m *Manager) SetObfuscation(cfg obfuscation.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.obfsCfg = cfg
}

// SessionSnapshot contains diagnostic info for an active session.
type SessionSnapshot struct {
	ID         string    `json:"id"`
	UUID       string    `json:"uuid"`
	Email      string    `json:"email"`
	RemoteAddr string    `json:"remote_addr"`
	StartTime  time.Time `json:"start_time"`
	Duration   string    `json:"duration"`
	TrafficIn  uint64    `json:"traffic_in"`
	TrafficOut uint64    `json:"traffic_out"`
}

// GetActiveSnapshots returns a list of current active clients (grouped by UUID and IP).
func (m *Manager) GetActiveSnapshots() []SessionSnapshot {
	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	policies := m.userPolicies
	m.mu.RUnlock()

	type clientKey struct {
		uuid [16]byte
		ip   string
	}

	// Group sessions by client (UUID + IP)
	groups := make(map[clientKey]*SessionSnapshot)
	now := time.Now()

	for _, s := range sessions {
		uuid := s.ClientUUID()
		remoteIP, _, _ := net.SplitHostPort(s.Connection().RemoteAddr().String())
		key := clientKey{uuid: uuid, ip: remoteIP}

		if snap, ok := groups[key]; ok {
			snap.TrafficIn += s.TrafficRecv.Load()
			snap.TrafficOut += s.TrafficSent.Load()
			if s.StartTime().Before(snap.StartTime) {
				snap.StartTime = s.StartTime()
				snap.Duration = now.Sub(s.StartTime()).Truncate(time.Second).String()
			}
		} else {
			fullHex := hex.EncodeToString(uuid[:])
			uuidStr := fmt.Sprintf("%s-%s-%s-%s-%s", 
				fullHex[0:8], fullHex[8:12], fullHex[12:16], fullHex[16:20], fullHex[20:])

			email := "unknown"
			if p, ok := policies[uuid]; ok {
				email = p.Email
			}

			groups[key] = &SessionSnapshot{
				ID:         s.id.String(),
				UUID:       uuidStr,
				Email:      email,
				RemoteAddr: remoteIP,
				StartTime:  s.StartTime(),
				Duration:   now.Sub(s.StartTime()).Truncate(time.Second).String(),
				TrafficIn:  s.TrafficRecv.Load(),
				TrafficOut: s.TrafficSent.Load(),
			}
		}
	}

	out := make([]SessionSnapshot, 0, len(groups))
	for _, snap := range groups {
		out = append(out, *snap)
	}
	return out
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
		uuid := s.ClientUUID()
		if p, ok := policies[uuid]; ok {
			if !p.Enabled {
				m.logger.Info("disconnecting disabled user during refresh", zap.String("uuid", hex.EncodeToString(uuid[:])))
				_ = s.CloseWithError(0x11, "user disabled")
				continue
			}
			s.ApplyRuntime(p.Mode, p.ObfsConfig)
			continue
		}
		s.ApplyRuntime(defaultMode, defaultObfs)
	}
}

func (m *Manager) EnforceQuotas() {
	m.mu.RLock()
	// 1. Snapshot policies and sessions
	policies := make(map[[16]byte]UserPolicy, len(m.userPolicies))
	for k, v := range m.userPolicies {
		policies[k] = v
	}
	allowedUUIDs := m.allowedUUIDs
	m.mu.RUnlock()

	m.mu.Lock()
	activeSessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		activeSessions = append(activeSessions, s)
	}
	m.mu.Unlock()

	// 2. Aggregate current usage per user
	liveUsage := make(map[[16]byte]uint64)
	for _, s := range activeSessions {
		liveUsage[s.ClientUUID()] += s.TrafficSent.Load() + s.TrafficRecv.Load()
	}

	// 3. Check and disconnect
	now := time.Now().Unix()
	for _, s := range activeSessions {
		uuid := s.ClientUUID()
		p, ok := policies[uuid]

		// Disconnect if user is disabled
		if ok && !p.Enabled {
			m.logger.Info("disconnecting disabled user", zap.String("email", p.Email), zap.String("uuid", hex.EncodeToString(uuid[:])))
			_ = s.CloseWithError(0x11, "user disabled")
			continue
		}

		// Disconnect if user was removed from policy (if server has allowlist enabled)
		if !ok && len(allowedUUIDs) > 0 {
			found := false
			for _, au := range allowedUUIDs {
				if au == uuid {
					found = true
					break
				}
			}
			if !found {
				m.logger.Info("disconnecting unauthorized user", zap.String("uuid", hex.EncodeToString(uuid[:])))
				_ = s.CloseWithError(0x11, "unauthorized uuid")
				continue
			}
		}

		if !ok {
			continue
		}

		// Time check
		if p.ExpireAtUnix > 0 && now > p.ExpireAtUnix {
			m.logger.Info("disconnecting expired user", zap.String("email", p.Email), zap.String("uuid", hex.EncodeToString(uuid[:])))
			_ = s.CloseWithError(0x10, "account expired")
			continue
		}

		// Volume check
		if p.DataLimit > 0 {
			total := p.BytesIn + p.BytesOut + liveUsage[uuid]
			if total >= uint64(p.DataLimit) {
				m.logger.Info("disconnecting user: quota reached", zap.String("email", p.Email), zap.Uint64("limit", uint64(p.DataLimit)))
				_ = s.CloseWithError(0x10, "data limit reached")
			}
		}
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
		cfg.BurstBytesMax = 64 * 1024
	case "masque":
		cfg.Enabled = true
		cfg.PaddingPct = 0.8
		cfg.MaxPaddingBytes = 1024
		cfg.MaxJitterMs = 20
		cfg.BurstBytesMax = 128 * 1024
	case "webtransport":
		cfg.Enabled = true
		cfg.PaddingPct = 0.9
		cfg.MaxPaddingBytes = 1280
		cfg.MaxJitterMs = 30
		cfg.BurstBytesMax = 256 * 1024
	case "ghost":
		cfg.Enabled = true
		cfg.PaddingPct = 1.0
		cfg.MaxPaddingBytes = 1024
		cfg.MaxJitterMs = 0
		cfg.BurstBytesMax = 0
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
	if cfg.PaddingPct == 0.8 && cfg.MaxPaddingBytes == 1024 {
		return "masque"
	}
	if cfg.PaddingPct == 0.9 && cfg.MaxPaddingBytes == 1280 {
		return "webtransport"
	}
	if cfg.PaddingPct == 1.0 && cfg.MaxJitterMs == 0 {
		return "ghost"
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
	case "masque":
		return 4
	case "webtransport":
		return 5
	case "ghost":
		return 6
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

	// Update IP tracking
	ip, _, _ := net.SplitHostPort(s.Connection().RemoteAddr().String())
	uuid := s.ClientUUID()
	if m.userIPs[uuid] == nil {
		m.userIPs[uuid] = make(map[string]int)
	}
	m.userIPs[uuid][ip]++
}
