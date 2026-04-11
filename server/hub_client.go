package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hivoid-org/hivoid-core/config"
	"github.com/hivoid-org/hivoid-core/geodata"
	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/session"
	gopsutilcpu "github.com/shirou/gopsutil/v4/cpu"
	gopsutilmem "github.com/shirou/gopsutil/v4/mem"
	"go.uber.org/zap"
)

// HubMessage represents a JSON message exchanged with the master Hub.
type HubMessage struct {
	Type          string          `json:"type"` // "SYNC", "REVOKE", "SHOCK", "CONFIG_UPDATE", "USAGE"
	Command       string          `json:"command,omitempty"`
	Event         string          `json:"event,omitempty"`
	RequestID     string          `json:"request_id,omitempty"`
	UUID          string          `json:"uuid,omitempty"`   // Included for REVOKE
	Users         []HubUserPolicy `json:"users,omitempty"`  // Included for SYNC
	Usage         []HubUserUsage  `json:"usage,omitempty"`  // Included for USAGE
	Config        json.RawMessage `json:"config,omitempty"` // For CONFIG_UPDATE
	Payload       json.RawMessage `json:"payload,omitempty"`
	Data          json.RawMessage `json:"data,omitempty"`
	TLS           json.RawMessage `json:"tls,omitempty"`
	GeoData       json.RawMessage `json:"geodata,omitempty"`
	GeoDataLegacy json.RawMessage `json:"geo_data,omitempty"`

	Domain             string `json:"domain,omitempty"`
	Email              string `json:"email,omitempty"`
	InstallType        string `json:"install_type,omitempty"`
	CloudflareAPIToken string `json:"cloudflare_api_token,omitempty"`
	GeoIPPath          string `json:"geoip_path,omitempty"`
	GeoSitePath        string `json:"geosite_path,omitempty"`
	CertFile           string `json:"cert_file,omitempty"`
	KeyFile            string `json:"key_file,omitempty"`
}

// HubUserPolicy is the configuration dictated by the Hub for a specific user.
type HubUserPolicy struct {
	UUID           string   `json:"uuid"`
	Email          string   `json:"email"`
	CertPin        string   `json:"cert_pin,omitempty"`
	Enabled        *bool    `json:"enabled,omitempty"`
	IsActive       *bool    `json:"is_active,omitempty"`
	BindIP         string   `json:"bind_ip"`
	Mode           string   `json:"mode"`
	Obfs           string   `json:"obfs"`
	MaxConnections int      `json:"max_connections"`
	MaxIPs         int      `json:"max_ips"`
	BandwidthLimit int64    `json:"bandwidth_limit"`
	BandwidthUnit  string   `json:"bandwidth_unit,omitempty"`
	DataLimit      int64    `json:"data_limit"`
	ExpireAtUnix   int64    `json:"expire_at_unix"`
	ExpireAt       string   `json:"expire_at,omitempty"`
	PoolSize       int      `json:"pool_size,omitempty"`
	SocksPort      int      `json:"socks_port,omitempty"`
	DNSPort        int      `json:"dns_port,omitempty"`
	DNSUpstream    string   `json:"dns_upstream,omitempty"`
	Insecure       *bool    `json:"insecure,omitempty"`
	BypassDomains  []string `json:"bypass_domains,omitempty"`
	BypassIPs      []string `json:"bypass_ips,omitempty"`
	DirectRoute    []string `json:"direct_route,omitempty"`
	GeoIPPath      string   `json:"geoip_path,omitempty"`
	GeoSitePath    string   `json:"geosite_path,omitempty"`
	BlockedHosts   []string `json:"blocked_hosts"`
	BlockedTags    []string `json:"blocked_tags"`
	DirectGeoSite  []string `json:"direct_geosite,omitempty"`
	DirectGeoIP    []string `json:"direct_geoip,omitempty"`
	DirectDomains  []string `json:"direct_domains,omitempty"`
	DirectIPs      []string `json:"direct_ips,omitempty"`
}

type hubTLSInstallRequest struct {
	Type               string `json:"type"`
	Domain             string `json:"domain"`
	Email              string `json:"email"`
	CloudflareAPIToken string `json:"cloudflare_api_token"`
	CertFile           string `json:"cert_file"`
	KeyFile            string `json:"key_file"`
}

type hubTLSSyncPathsRequest struct {
	Domain   string `json:"domain"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type hubGeodataInstallRequest struct {
	GeoIPPath   string `json:"geoip_path"`
	GeoSitePath string `json:"geosite_path"`
}

type hubConfigPatch struct {
	Server        json.RawMessage            `json:"server"`
	Security      json.RawMessage            `json:"security"`
	TLS           json.RawMessage            `json:"tls"`
	GeoData       json.RawMessage            `json:"geodata"`
	GeoDataLegacy json.RawMessage            `json:"geo_data"`
	Features      json.RawMessage            `json:"features"`
	Port          *int                       `json:"port"`
	Name          *string                    `json:"name"`
	Obfs          *string                    `json:"obfs"`
	Cert          *string                    `json:"cert"`
	Key           *string                    `json:"key"`
	Mode          *string                    `json:"mode"`
	MaxConns      *int                       `json:"max_conns"`
	AllowedHosts  *[]string                  `json:"allowed_hosts"`
	BlockedHosts  *[]string                  `json:"blocked_hosts"`
	BlockedTags   *[]string                  `json:"blocked_tags"`
	AntiProbe     *bool                      `json:"anti_probe"`
	FallbackAddr  *string                    `json:"fallback_addr"`
	GeoIPPath     *string                    `json:"geoip_path"`
	GeoSitePath   *string                    `json:"geosite_path"`
	Users         *[]config.ServerUserConfig `json:"users"`

	ListenAddr         *string `json:"listen_addr"`
	ServerMode         *string `json:"server_mode"`
	LogLevel           *string `json:"log_level"`
	CertFile           *string `json:"cert_file"`
	KeyFile            *string `json:"key_file"`
	HotReload          *bool   `json:"hot_reload"`
	ConnectionTracking *bool   `json:"connection_tracking"`
	DisconnectExpired  *bool   `json:"disconnect_expired"`
	PublicHost         *string `json:"public_host"`
	IsActive           *bool   `json:"is_active"`
}

// HubUserUsage reports current traffic telemetry up to the Hub.
type HubUserUsage struct {
	UUID           string   `json:"uuid"`
	Email          string   `json:"email,omitempty"`
	BytesIn        uint64   `json:"bytes_in"`
	BytesOut       uint64   `json:"bytes_out"`
	DataLimit      int64    `json:"data_limit"`
	MaxIPs         int      `json:"max_ips"`
	MaxConnections int      `json:"max_connections"`
	RequestPool    int      `json:"request_pool"`
	ConnectedAt    int64    `json:"connected_at"`
	SrcIP          string   `json:"src_ip"`
	BlockedHosts   []string `json:"blocked_hosts,omitempty"`
	BlockedTags    []string `json:"blocked_tags,omitempty"`
}

type hubInstallResult struct {
	Type      string         `json:"type"`
	RequestID string         `json:"request_id"`
	Kind      string         `json:"kind"`
	Status    string         `json:"status"`
	Message   string         `json:"message"`
	CertPin   string         `json:"cert_pin,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

type hubCommandAck struct {
	Type       string `json:"type"`
	RequestID  string `json:"request_id,omitempty"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	ReceivedAt string `json:"received_at"`
}

type hubCommandResult struct {
	Type       string         `json:"type"`
	RequestID  string         `json:"request_id,omitempty"`
	Kind       string         `json:"kind"`
	Status     string         `json:"status"`
	Message    string         `json:"message"`
	FinishedAt string         `json:"finished_at"`
	Details    map[string]any `json:"details,omitempty"`
}

type hubReportStats struct {
	ActiveConnections    int     `json:"active_connections"`
	CPUPercent           float64 `json:"cpu_percent"`
	MemoryPercent        float64 `json:"memory_percent"`
	UptimeSeconds        int64   `json:"uptime_seconds"`
	MemoryBytes          uint64  `json:"memory_bytes"`
	ProcessCPUPercent    float64 `json:"process_cpu_percent,omitempty"`
	ProcessMemoryBytes   uint64  `json:"process_memory_bytes,omitempty"`
	SystemCPUPercent     float64 `json:"system_cpu_percent,omitempty"`
	SystemMemoryPercent  float64 `json:"system_memory_percent,omitempty"`
	SystemMemoryUsedByte uint64  `json:"system_memory_used_bytes,omitempty"`
	SystemMemoryTotByte  uint64  `json:"system_memory_total_bytes,omitempty"`
}

type hubReportMessage struct {
	Type               string         `json:"type"`
	CertPin            string         `json:"cert_pin,omitempty"`
	CertExpiresAt      string         `json:"cert_expires_at,omitempty"`
	ConnectedAt        string         `json:"connected_at,omitempty"`
	ReportedAt         string         `json:"reported_at,omitempty"`
	ReportIntervalMS   int            `json:"report_interval_ms"`
	CPUUsage           float64        `json:"cpu_usage"`
	RAMUsage           float64        `json:"ram_usage"`
	RAMUsageMB         float64        `json:"ram_usage_mb"`
	Uptime             string         `json:"uptime"`
	UptimeSeconds      int64          `json:"uptime_seconds"`
	ProcessCPUUsage    float64        `json:"process_cpu_usage"`
	ProcessRAMUsageMB  float64        `json:"process_ram_usage_mb"`
	ProcessRAMUsageB   uint64         `json:"process_ram_usage_bytes"`
	SystemCPUUsage     float64        `json:"system_cpu_usage"`
	SystemRAMUsage     float64        `json:"system_ram_usage"`
	SystemRAMUsageMB   float64        `json:"system_ram_usage_mb"`
	SystemRAMTotalMB   float64        `json:"system_ram_total_mb"`
	SystemRAMUsedBytes uint64         `json:"system_ram_used_bytes"`
	SystemRAMTotBytes  uint64         `json:"system_ram_total_bytes"`
	Stats              hubReportStats `json:"stats"`
}

// HubClient manages the stateful connection to the Subscription Hub.
type HubClient struct {
	cfg            config.HubConfig
	manager        *session.Manager
	usrCtrls       *UserControlManager
	logger         *zap.Logger
	applyCfg       func(*config.ServerConfig) error
	onSyncPolicies func(map[[16]byte]session.UserPolicy)
	usageMu        sync.Mutex
	lastOnline     map[[16]byte]HubUserUsage
	startTime      time.Time
	cpuMu          sync.Mutex
	lastCPUSample  float64
	lastCPUAt      time.Time
	hasCPUSample   bool

	runtimeMu  sync.RWMutex
	runtimeCfg *config.ServerConfig

	mu   sync.Mutex
	conn *websocket.Conn

	ctx    context.Context
	cancel context.CancelFunc
}

// NewHubClient initializes the WSS Hub Client subsystem.
func NewHubClient(cfg config.HubConfig, m *session.Manager, uc *UserControlManager, logger *zap.Logger, applyCfg func(*config.ServerConfig) error, onSyncPolicies func(map[[16]byte]session.UserPolicy), baseCfg *config.ServerConfig) *HubClient {
	ctx, cancel := context.WithCancel(context.Background())
	if m != nil {
		m.SetRequireKnownPolicy(true)
	}
	return &HubClient{
		cfg:            cfg,
		manager:        m,
		usrCtrls:       uc,
		logger:         logger.With(zap.String("component", "hub")),
		applyCfg:       applyCfg,
		onSyncPolicies: onSyncPolicies,
		lastOnline:     make(map[[16]byte]HubUserUsage),
		startTime:      time.Now(),
		runtimeCfg:     cloneServerConfig(baseCfg),
		ctx:            ctx,
		cancel:         cancel,
	}
}

// Start spawns the background connection loop.
func (h *HubClient) Start() {
	go h.connectLoop()
}

// Stop cleanly shuts down the Hub Client.
func (h *HubClient) Stop() {
	h.cancel()
	h.mu.Lock()
	if h.conn != nil {
		_ = h.conn.Close()
	}
	h.mu.Unlock()
}

func (h *HubClient) connectLoop() {
	for {
		if h.ctx.Err() != nil {
			return
		}

		targetURLs := []string{h.cfg.Endpoint}
		nodeID := h.currentNodeID()

		headers := http.Header{}
		headers.Add("X-Hub-Token", h.cfg.NodeToken)
		headers.Add("Authorization", "Bearer "+h.cfg.NodeToken)
		if nodeID != "" {
			headers.Add("X-Node-ID", nodeID)
		}

		dialer := *websocket.DefaultDialer
		if h.cfg.Insecure {
			dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}

		// Build hub-compatible WS URLs and pass token in query as fallback.
		u, err := url.Parse(h.cfg.Endpoint)
		if err == nil {
			pathCandidates := normalizeHubWebSocketPaths(u.Path)
			targetURLs = make([]string, 0, len(pathCandidates))
			for _, path := range pathCandidates {
				candidate := *u
				candidate.Path = path
				q := candidate.Query()
				q.Set("token", h.cfg.NodeToken)
				if nodeID != "" {
					q.Set("node_id", nodeID)
				}
				candidate.RawQuery = q.Encode()
				targetURLs = append(targetURLs, candidate.String())
			}
		}

		var conn *websocket.Conn
		var connectedEndpoint string
		var lastErr error
		for _, targetURL := range targetURLs {
			h.logger.Info("connecting to hub via websocket", zap.String("endpoint", targetURL))
			c, _, dialErr := dialer.DialContext(h.ctx, targetURL, headers)
			if dialErr == nil {
				conn = c
				connectedEndpoint = targetURL
				break
			}
			lastErr = dialErr
			h.logger.Warn("hub dial attempt failed", zap.String("endpoint", targetURL), zap.Error(dialErr))
		}
		if conn == nil {
			h.logger.Error("hub connection failed, retrying in 5s...", zap.Error(lastErr))
			select {
			case <-time.After(5 * time.Second):
			case <-h.ctx.Done():
				return
			}
			continue
		}

		h.logger.Info("connected to hub successfully, awaiting SYNC", zap.String("endpoint", connectedEndpoint))
		h.mu.Lock()
		h.conn = conn
		h.mu.Unlock()

		if err := h.sendNodeReport(); err != nil {
			h.logger.Error("failed to send startup REPORT", zap.Error(err))
			_ = conn.Close()
			select {
			case <-time.After(2 * time.Second):
			case <-h.ctx.Done():
				return
			}
			continue
		}

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			h.readLoop(conn)
		}()

		go func() {
			defer wg.Done()
			h.telemetryLoop(conn)
		}()

		// Wait for either readLoop to fail (connection drop) or context cancel
		wg.Wait()

		h.mu.Lock()
		h.conn = nil
		h.mu.Unlock()
		h.logger.Warn("hub connection lost, reconnecting in 2s...")

		select {
		case <-time.After(2 * time.Second):
		case <-h.ctx.Done():
			return
		}
	}
}

func (h *HubClient) readLoop(conn *websocket.Conn) {
	for {
		var msg HubMessage
		if err := conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				h.logger.Error("hub connection read error", zap.Error(err))
			}
			_ = conn.Close()
			return
		}

		msgType := resolveHubMessageType(msg)
		switch msgType {
		case "SYNC":
			h.handleSync(resolveHubSyncUsers(msg))
		case "REVOKE":
			h.handleRevoke(resolveHubRevokeUUID(msg))
		case "SHOCK":
			h.handleShock()
		case "CONFIG_UPDATE":
			h.handleConfigUpdate(msg)
		case "GEODATA_INSTALL":
			h.handleGeodataInstall(msg)
		case "TLS_INSTALL":
			h.handleTLSInstall(msg)
		case "TLS_SYNC_PATHS":
			if err := h.handleTLSSyncPaths(msg); err != nil {
				h.logger.Warn("failed to handle TLS_SYNC_PATHS", zap.Error(err))
			}
		default:
			h.logger.Warn("unknown hub message type", zap.String("type", msgType), zap.String("raw_type", msg.Type), zap.String("command", msg.Command), zap.String("event", msg.Event))
		}
	}
}

func resolveHubRequestID(msg HubMessage) string {
	if reqID := strings.TrimSpace(msg.RequestID); reqID != "" {
		return reqID
	}

	for _, raw := range commandPayloadCandidates(msg.Payload, msg.Data, msg.Config, msg.TLS, msg.GeoData, msg.GeoDataLegacy) {
		var container struct {
			RequestID string `json:"request_id"`
		}
		if !decodeRaw(raw, &container) {
			continue
		}
		if reqID := strings.TrimSpace(container.RequestID); reqID != "" {
			return reqID
		}
	}

	return ""
}

func resolveHubMessageType(msg HubMessage) string {
	t := strings.ToUpper(strings.TrimSpace(msg.Type))
	cmd := strings.ToUpper(strings.TrimSpace(msg.Command))
	evt := strings.ToUpper(strings.TrimSpace(msg.Event))

	if t == "" {
		if cmd != "" {
			return cmd
		}
		return evt
	}

	if t == "COMMAND" || t == "CMD" || t == "EVENT" || t == "MESSAGE" {
		if cmd != "" {
			return cmd
		}
		if evt != "" {
			return evt
		}
	}

	return t
}

func resolveHubSyncUsers(msg HubMessage) []HubUserPolicy {
	if len(msg.Users) > 0 {
		return msg.Users
	}

	for _, raw := range commandPayloadCandidates(msg.Payload, msg.Data, msg.Config) {
		trimmed := strings.TrimSpace(string(raw))
		if trimmed == "" || trimmed == "null" {
			continue
		}

		var users []HubUserPolicy
		if err := json.Unmarshal(raw, &users); err == nil && len(users) > 0 {
			return users
		}

		var container struct {
			Users []HubUserPolicy `json:"users"`
		}
		if err := json.Unmarshal(raw, &container); err == nil && len(container.Users) > 0 {
			return container.Users
		}
	}

	return nil
}

func resolveHubRevokeUUID(msg HubMessage) string {
	if strings.TrimSpace(msg.UUID) != "" {
		return strings.TrimSpace(msg.UUID)
	}
	for _, raw := range commandPayloadCandidates(msg.Payload, msg.Data, msg.Config) {
		var container struct {
			UUID string `json:"uuid"`
		}
		if !decodeRaw(raw, &container) {
			continue
		}
		if strings.TrimSpace(container.UUID) != "" {
			return strings.TrimSpace(container.UUID)
		}
	}
	return ""
}

func resolveHubConfigPayload(msg HubMessage) json.RawMessage {
	candidates := commandPayloadCandidates(msg.Config, msg.Payload, msg.Data)
	for _, raw := range candidates {
		if looksLikeConfigPatch(raw) {
			return raw
		}
	}
	for _, raw := range candidates {
		if strings.TrimSpace(string(raw)) != "" && strings.TrimSpace(string(raw)) != "null" {
			return raw
		}
	}
	return nil
}

func (h *HubClient) handleSync(users []HubUserPolicy) {
	policies := make(map[[16]byte]session.UserPolicy)
	for _, u := range users {
		normalized := normalizeHubUserPolicy(u)
		if !isValidHubMode(normalized.Mode) {
			h.logger.Warn("invalid mode in hub policy; skipping user", zap.String("uuid", normalized.UUID), zap.String("mode", normalized.Mode))
			continue
		}
		if !isValidHubObfs(normalized.Obfs) {
			h.logger.Warn("invalid obfs in hub policy; skipping user", zap.String("uuid", normalized.UUID), zap.String("obfs", normalized.Obfs))
			continue
		}
		enabled := resolveHubUserEnabled(normalized)
		expireAtUnix, ok := resolveHubExpireAtUnix(normalized)
		if !ok {
			h.logger.Warn("invalid expire_at from hub", zap.String("uuid", normalized.UUID), zap.String("expire_at", strings.TrimSpace(normalized.ExpireAt)))
			expireAtUnix = 0
		}
		uuid, err := parseUUID(normalized.UUID)
		if err != nil {
			h.logger.Warn("invalid uuid format from hub", zap.String("uuid", normalized.UUID))
			continue
		}
		policies[uuid] = session.UserPolicy{
			UUID:           uuid,
			Email:          normalized.Email,
			CertPin:        normalized.CertPin,
			Enabled:        enabled,
			Mode:           intelligence.ModeFromString(normalized.Mode),
			ObfsConfig:     session.ObfsConfigForName(normalized.Obfs),
			MaxConnections: normalized.MaxConnections,
			MaxIPs:         normalized.MaxIPs,
			BindIP:         normalized.BindIP,
			BandwidthLimit: normalized.BandwidthLimit,
			DataLimit:      normalized.DataLimit,
			ExpireAtUnix:   expireAtUnix,
			BlockedHosts:   append([]string(nil), normalized.BlockedHosts...),
			BlockedTags:    append([]string(nil), normalized.BlockedTags...),
			DirectGeoSite:  append([]string(nil), normalized.DirectGeoSite...),
			DirectGeoIP:    append([]string(nil), normalized.DirectGeoIP...),
			DirectDomains:  append([]string(nil), normalized.DirectDomains...),
			DirectIPs:      append([]string(nil), normalized.DirectIPs...),
		}
		h.logger.Debug("hub user policy normalized",
			zap.String("uuid", normalized.UUID),
			zap.String("email", normalized.Email),
			zap.String("cert_pin", normalized.CertPin),
			zap.Int64("bandwidth_limit_kbytes_per_sec", normalized.BandwidthLimit),
			zap.String("bandwidth_unit", normalized.BandwidthUnit),
		)
	}

	allowedUUIDs := enabledPolicyUUIDs(policies)

	// 1. Atomically update the memory policies
	h.manager.SetAllowedUUIDs(allowedUUIDs)
	h.manager.SetUserPolicies(policies)
	h.usrCtrls.ApplyPolicies(policies)
	if h.onSyncPolicies != nil {
		h.onSyncPolicies(policies)
	}

	// 2. Refresh active sessions (kick ones that are no longer allowed/enabled)
	h.manager.RefreshActiveSessionPolicies()
	h.manager.EnforceQuotas()

	h.logger.Info("synchronized policies from hub", zap.Int("active_users", len(policies)))
}

func normalizeHubUserPolicy(u HubUserPolicy) HubUserPolicy {
	u.UUID = strings.TrimSpace(u.UUID)
	u.Email = strings.TrimSpace(u.Email)
	u.CertPin = normalizeCertPin(strings.TrimSpace(u.CertPin))
	u.BindIP = strings.TrimSpace(u.BindIP)
	u.Mode = strings.TrimSpace(u.Mode)
	u.Obfs = strings.TrimSpace(u.Obfs)
	u.BandwidthUnit = strings.TrimSpace(u.BandwidthUnit)
	u.ExpireAt = strings.TrimSpace(u.ExpireAt)
	u.DNSUpstream = strings.TrimSpace(u.DNSUpstream)
	u.GeoIPPath = strings.TrimSpace(u.GeoIPPath)
	u.GeoSitePath = strings.TrimSpace(u.GeoSitePath)
	if u.Mode == "" {
		u.Mode = "adaptive"
	}
	u.BypassDomains = normalizeStringList(u.BypassDomains)
	u.BypassIPs = normalizeStringList(u.BypassIPs)
	u.DirectRoute = normalizeStringList(u.DirectRoute)
	u.BlockedHosts = normalizeStringList(u.BlockedHosts)
	u.BlockedTags = normalizeStringList(u.BlockedTags)
	u.DirectGeoSite = normalizeStringList(append(u.DirectGeoSite, u.DirectRoute...))
	u.DirectGeoIP = normalizeStringList(append(u.DirectGeoIP, u.DirectRoute...))
	u.DirectDomains = normalizeStringList(append(u.DirectDomains, u.BypassDomains...))
	u.DirectIPs = normalizeStringList(append(u.DirectIPs, u.BypassIPs...))

	if u.MaxConnections <= 0 {
		u.MaxConnections = 0
	}
	if u.MaxIPs <= 0 {
		u.MaxIPs = 0
	}
	if u.BandwidthLimit <= 0 {
		u.BandwidthLimit = 0
	} else {
		u.BandwidthLimit = normalizeHubBandwidthLimitToKBytesPerSec(u.BandwidthLimit, u.BandwidthUnit)
	}
	if u.DataLimit <= 0 {
		u.DataLimit = 0
	}
	if u.ExpireAtUnix <= 0 {
		u.ExpireAtUnix = 0
	}

	return u
}

func normalizeHubBandwidthLimitToKBytesPerSec(limit int64, unit string) int64 {
	if limit <= 0 {
		return 0
	}

	toKBytes := func(v int64) int64 {
		if v <= 0 {
			return 0
		}
		return v
	}
	fromKBits := func(v int64) int64 {
		if v <= 0 {
			return 0
		}
		kb := (v + 7) / 8
		if kb <= 0 {
			return 1
		}
		return kb
	}
	fromBytes := func(v int64) int64 {
		if v <= 0 {
			return 0
		}
		kb := (v + 1023) / 1024
		if kb <= 0 {
			return 1
		}
		return kb
	}

	u := strings.ToLower(strings.TrimSpace(unit))
	switch u {
	case "", "kbps", "kbit/s", "kbits/s", "kibps":
		// Hub default: bandwidth_limit is in kbps.
		return fromKBits(limit)
	case "kb/s", "kbyte/s", "kbytes/s", "kb", "kib/s", "kibytes/s", "kib":
		return toKBytes(limit)
	case "mbps", "mbit/s", "mbits/s", "mibps":
		return fromKBits(limit * 1024)
	case "mb/s", "mbyte/s", "mbytes/s", "mib/s", "mibytes/s":
		return toKBytes(limit * 1024)
	case "bps", "bit/s", "bits/s":
		return fromBytes((limit + 7) / 8)
	case "bytes/s", "byte/s", "b/s", "bps_bytes":
		return fromBytes(limit)
	default:
		// Unknown unit -> stay backward compatible with previous core behavior (KB/s).
		return toKBytes(limit)
	}
}

func isValidHubMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "performance", "high_performance", "stealth", "balanced", "adaptive":
		return true
	default:
		return false
	}
}

func isValidHubObfs(obfs string) bool {
	switch strings.ToLower(strings.TrimSpace(obfs)) {
	case "", "none", "random", "http", "tls", "masque", "webtransport", "ghost":
		return true
	default:
		return false
	}
}

func resolveHubUserEnabled(u HubUserPolicy) bool {
	if u.Enabled != nil {
		return *u.Enabled
	}
	if u.IsActive != nil {
		return *u.IsActive
	}
	return true
}

func resolveHubExpireAtUnix(u HubUserPolicy) (int64, bool) {
	if u.ExpireAtUnix > 0 {
		return u.ExpireAtUnix, true
	}
	if u.ExpireAt == "" {
		return 0, true
	}
	t, err := time.Parse(time.RFC3339, u.ExpireAt)
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}

func enabledPolicyUUIDs(policies map[[16]byte]session.UserPolicy) [][16]byte {
	allowed := make([][16]byte, 0, len(policies))
	for uuid, p := range policies {
		if p.Enabled {
			allowed = append(allowed, uuid)
		}
	}
	return allowed
}

func (h *HubClient) handleRevoke(uuidStr string) {
	uuid, err := parseUUID(uuidStr)
	if err != nil {
		h.logger.Warn("invalid revoke uuid format", zap.String("uuid", uuidStr))
		return
	}
	h.logger.Info("hub command: revoking user session", zap.String("uuid", uuidStr))
	// Force disconnect all streams immediately
	h.manager.KickUser(uuid)
}

func (h *HubClient) handleShock() {
	h.logger.Info("hub command: shock (kicking all sessions)")
	h.manager.KickAll()
}

func (h *HubClient) handleConfigUpdate(msg HubMessage) {
	requestID := resolveHubRequestID(msg)
	rawConfig := resolveHubConfigPayload(msg)
	h.emitCommandAck(requestID, "CONFIG_UPDATE", "config update accepted")

	h.logger.Info("hub command: config update (hot reload)")
	if h.applyCfg == nil {
		h.logger.Warn("config update received but applyCfg is not configured")
		h.emitCommandResult(requestID, "CONFIG_UPDATE", "failed", "config update callback is not configured", map[string]any{"error_code": "CONFIG_APPLY_CALLBACK_MISSING"})
		return
	}

	prevCfg := h.getRuntimeConfig()
	nextCfg, patch, err := h.buildConfigUpdate(rawConfig)
	if err != nil {
		h.logger.Error("failed to parse hub config update", zap.Error(err))
		h.emitCommandResult(requestID, "CONFIG_UPDATE", "failed", "config update payload parse failed", map[string]any{"error_code": "CONFIG_PARSE_FAILED", "error": err.Error()})
		return
	}

	if patch.IsActive != nil && !*patch.IsActive {
		h.logger.Warn("hub config marks node inactive; runtime keeps node online until explicit stop")
	}
	if patch.PublicHost != nil {
		h.logger.Info("hub config includes public_host metadata", zap.String("public_host", strings.TrimSpace(*patch.PublicHost)))
	}

	fallbackMissingTLSForConfigUpdate(nextCfg, prevCfg, h.logger)

	if err := nextCfg.ValidateServer(); err != nil {
		h.logger.Error("hub config update validation failed", zap.Error(err))
		h.emitCommandResult(requestID, "CONFIG_UPDATE", "failed", "config update validation failed", map[string]any{"error_code": "CONFIG_VALIDATE_FAILED", "error": err.Error()})
		return
	}

	if err := h.applyCfg(nextCfg); err != nil {
		h.logger.Error("failed to apply hub config update", zap.Error(err))
		h.emitCommandResult(requestID, "CONFIG_UPDATE", "failed", "config update apply failed", map[string]any{"error_code": "CONFIG_APPLY_FAILED", "error": err.Error()})
	} else {
		h.setRuntimeConfig(nextCfg)
		h.logger.Info("hub config update applied successfully")
		h.emitCommandResult(requestID, "CONFIG_UPDATE", "success", "config update applied", nil)
		if err := h.sendNodeReport(); err != nil {
			h.logger.Warn("failed to send REPORT after config update", zap.Error(err))
		}
	}
}

func (h *HubClient) handleGeodataInstall(msg HubMessage) {
	requestID := resolveHubRequestID(msg)
	h.emitCommandAck(requestID, "GEODATA_INSTALL", "geodata install accepted")
	sendFailed := func(message string, details map[string]any) {
		h.emitInstallResult(requestID, "GEODATA_INSTALL", "failed", message, "", details)
	}
	sendSuccess := func(message string, details map[string]any) {
		h.emitInstallResult(requestID, "GEODATA_INSTALL", "success", message, "", details)
	}

	req := decodeGeodataInstallRequest(msg)
	next := h.getRuntimeConfig()
	if next == nil {
		next = defaultRuntimeConfig()
	}

	geoIPPath := firstNonEmpty(req.GeoIPPath, next.GeoIPPath, "/var/lib/hivoid/geoip.dat")
	geoSitePath := firstNonEmpty(req.GeoSitePath, next.GeoSitePath, "/var/lib/hivoid/geosite.dat")
	if strings.TrimSpace(geoIPPath) == "" || strings.TrimSpace(geoSitePath) == "" {
		sendFailed("geodata paths are missing", map[string]any{"geoip_path": req.GeoIPPath, "geosite_path": req.GeoSitePath, "error_code": "GEODATA_PATH_MISSING"})
		return
	}

	geoIPSource, geoSiteSource, err := ensureGeodataAssets(geoIPPath, geoSitePath)
	if err != nil {
		h.logger.Error("GEODATA_INSTALL prepare failed", zap.String("geoip_path", geoIPPath), zap.String("geosite_path", geoSitePath), zap.Error(err))
		sendFailed("GeoData installation failed", map[string]any{"geoip_path": geoIPPath, "geosite_path": geoSitePath, "error_code": "GEODATA_INSTALL_FAILED", "error": err.Error()})
		return
	}

	next.GeoIPPath = geoIPPath
	next.GeoSitePath = geoSitePath

	if err := h.applyRuntimeConfig(next); err != nil {
		h.logger.Error("failed to apply GEODATA_INSTALL", zap.Error(err))
		sendFailed("GeoData runtime apply failed", map[string]any{"geoip_path": geoIPPath, "geosite_path": geoSitePath, "error_code": "GEODATA_APPLY_FAILED", "error": err.Error()})
		return
	}

	h.logger.Info("GEODATA_INSTALL applied", zap.String("geoip_path", next.GeoIPPath), zap.String("geosite_path", next.GeoSitePath))
	sendSuccess("GeoData files downloaded and verified", map[string]any{"geoip_path": next.GeoIPPath, "geosite_path": next.GeoSitePath, "geoip_source": geoIPSource, "geosite_source": geoSiteSource})
}

func (h *HubClient) handleTLSSyncPaths(msg HubMessage) error {
	req := decodeTLSSyncPathsRequest(msg)
	domain := resolveNodeDomain(req.Domain, h)

	certFile := req.CertFile
	keyFile := req.KeyFile
	if certFile == "" || keyFile == "" {
		if domain != "" {
			certFile, keyFile = letsEncryptPaths(domain)
		}
	}

	if certFile == "" || keyFile == "" {
		return fmt.Errorf("TLS_SYNC_PATHS missing cert/key paths for domain %q", domain)
	}
	if !fileExists(certFile) || !fileExists(keyFile) {
		return fmt.Errorf("TLS_SYNC_PATHS target files not found cert=%q key=%q", certFile, keyFile)
	}

	next := h.getRuntimeConfig()
	if next == nil {
		next = defaultRuntimeConfig()
	}
	next.Cert = certFile
	next.Key = keyFile

	if err := h.applyRuntimeConfig(next); err != nil {
		return fmt.Errorf("failed to apply TLS_SYNC_PATHS: %w", err)
	}
	h.logger.Info("TLS paths synchronized", zap.String("cert", certFile), zap.String("key", keyFile))
	if err := h.sendNodeReport(); err != nil {
		h.logger.Warn("failed to send REPORT after TLS_SYNC_PATHS", zap.Error(err))
	}
	return nil
}

func (h *HubClient) handleTLSInstall(msg HubMessage) {
	requestID := resolveHubRequestID(msg)
	h.emitCommandAck(requestID, "TLS_INSTALL", "tls install accepted")
	sendFailed := func(message string, details map[string]any) {
		h.emitInstallResult(requestID, "TLS_INSTALL", "failed", message, "", details)
	}
	sendSuccess := func(message, certPin string, details map[string]any) {
		h.emitInstallResult(requestID, "TLS_INSTALL", "success", message, certPin, details)
	}

	req := decodeTLSInstallRequest(msg)
	domain := resolveNodeDomain(req.Domain, h)
	if domain == "" {
		sendFailed("TLS domain is missing", map[string]any{"error_code": "TLS_DOMAIN_MISSING"})
		return
	}

	if !nodeAutoinstallEnabled() {
		h.logger.Warn("TLS_INSTALL received but auto-install is disabled by environment", zap.String("domain", domain))
		err := h.handleTLSSyncPaths(HubMessage{Domain: domain, CertFile: req.CertFile, KeyFile: req.KeyFile, TLS: msg.TLS, Payload: msg.Payload, Data: msg.Data, Config: msg.Config})
		if err != nil {
			sendFailed("TLS sync paths failed while auto-install is disabled", map[string]any{"domain": domain, "error_code": "TLS_SYNC_PATHS_FAILED", "error": err.Error()})
			return
		}
		currentCfg := h.getRuntimeConfig()
		certFile := ""
		keyFile := ""
		if currentCfg != nil {
			certFile = strings.TrimSpace(currentCfg.Cert)
			keyFile = strings.TrimSpace(currentCfg.Key)
		}
		certPin, expiresAt, err := certPinFromPEMFile(certFile)
		if err != nil {
			sendFailed("TLS paths synchronized but cert pin calculation failed", map[string]any{"domain": domain, "cert_file": certFile, "key_file": keyFile, "error_code": "CERT_PIN_CALC_FAILED", "error": err.Error()})
			return
		}
		sendSuccess("TLS paths synchronized while auto-install is disabled", certPin, map[string]any{"domain": domain, "cert_file": certFile, "key_file": keyFile, "cert_pin": certPin, "expires_at": expiresAt})
		return
	}

	installType := strings.ToLower(strings.TrimSpace(req.Type))
	if installType == "" {
		installType = "openssl_self_signed"
	}

	var certFile, keyFile string
	var err error
	switch installType {
	case "openssl_self_signed":
		certFile, keyFile, err = installOpenSSLCert(domain)
	case "cloudflare":
		token := req.CloudflareAPIToken
		if token == "" {
			token = strings.TrimSpace(os.Getenv("HIVOID_CLOUDFLARE_API_TOKEN"))
		}
		certFile, keyFile, err = installCloudflareCert(domain, req.Email, token)
	default:
		sendFailed("Unsupported TLS install type", map[string]any{"domain": domain, "type": req.Type, "error_code": "TLS_TYPE_UNSUPPORTED"})
		return
	}
	if err != nil {
		h.logger.Error("TLS_INSTALL failed", zap.String("type", installType), zap.String("domain", domain), zap.Error(err))
		sendFailed("TLS installation failed", map[string]any{"domain": domain, "type": installType, "error_code": "TLS_INSTALL_FAILED", "error": err.Error()})
		return
	}

	if err := h.handleTLSSyncPaths(HubMessage{Domain: domain, CertFile: certFile, KeyFile: keyFile}); err != nil {
		h.logger.Error("TLS_INSTALL applied cert but sync failed", zap.String("domain", domain), zap.Error(err))
		sendFailed("TLS installed but runtime sync failed", map[string]any{"domain": domain, "type": installType, "cert_file": certFile, "key_file": keyFile, "error_code": "TLS_SYNC_PATHS_FAILED", "error": err.Error()})
		return
	}

	certPin, expiresAt, err := certPinFromPEMFile(certFile)
	if err != nil {
		h.logger.Error("TLS_INSTALL cert pin calculation failed", zap.String("domain", domain), zap.String("cert_file", certFile), zap.Error(err))
		sendFailed("TLS installed but cert pin calculation failed", map[string]any{"domain": domain, "type": installType, "cert_file": certFile, "key_file": keyFile, "error_code": "CERT_PIN_CALC_FAILED", "error": err.Error()})
		return
	}

	sendSuccess("TLS installed and synchronized", certPin, map[string]any{"domain": domain, "type": installType, "cert_file": certFile, "key_file": keyFile, "cert_pin": certPin, "expires_at": expiresAt})
}

func (h *HubClient) applyRuntimeConfig(next *config.ServerConfig) error {
	if h.applyCfg == nil {
		return fmt.Errorf("runtime apply callback is not configured")
	}
	normalizeRuntimeConfig(next)
	if err := next.ValidateServer(); err != nil {
		return err
	}
	if err := h.applyCfg(next); err != nil {
		return err
	}
	h.setRuntimeConfig(next)
	return nil
}

func (h *HubClient) emitCommandAck(requestID, kind, message string) {
	ack := hubCommandAck{
		Type:       "COMMAND_ACK",
		RequestID:  requestID,
		Kind:       kind,
		Status:     "accepted",
		Message:    message,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := h.writeHubJSON(ack); err != nil {
		h.logger.Warn("failed to send COMMAND_ACK", zap.String("request_id", requestID), zap.String("kind", kind), zap.Error(err))
		return
	}
	h.logger.Debug("COMMAND_ACK sent", zap.String("request_id", requestID), zap.String("kind", kind))
}

func (h *HubClient) emitCommandResult(requestID, kind, status, message string, details map[string]any) {
	res := hubCommandResult{
		Type:       "COMMAND_RESULT",
		RequestID:  requestID,
		Kind:       kind,
		Status:     status,
		Message:    message,
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		Details:    details,
	}
	if err := h.writeHubJSON(res); err != nil {
		h.logger.Warn("failed to send COMMAND_RESULT", zap.String("request_id", requestID), zap.String("kind", kind), zap.String("status", status), zap.Error(err))
		return
	}
	h.logger.Debug("COMMAND_RESULT sent", zap.String("request_id", requestID), zap.String("kind", kind), zap.String("status", status))
}

func (h *HubClient) emitInstallResult(requestID, kind, status, message, certPin string, details map[string]any) {
	res := hubInstallResult{
		Type:      "INSTALL_RESULT",
		RequestID: requestID,
		Kind:      kind,
		Status:    status,
		Message:   message,
		CertPin:   normalizeCertPin(certPin),
		Details:   details,
	}
	if err := h.writeHubJSON(res); err != nil {
		h.logger.Error("failed to send INSTALL_RESULT", zap.String("request_id", requestID), zap.String("kind", kind), zap.String("status", status), zap.Error(err))
		return
	}
	h.logger.Info("INSTALL_RESULT sent", zap.String("request_id", requestID), zap.String("kind", kind), zap.String("status", status))
}

func (h *HubClient) writeHubJSON(v any) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conn == nil {
		return fmt.Errorf("hub connection is not available")
	}
	h.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := h.conn.WriteJSON(v); err != nil {
		return err
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v != "" {
			return v
		}
	}
	return ""
}

func ensureGeodataAssets(geoIPPath, geoSitePath string) (geoIPSource string, geoSiteSource string, err error) {
	geoIPSource, err = ensureGeodataFile(geoIPPath, []string{
		"https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
		"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
	})
	if err != nil {
		return "", "", err
	}

	geoSiteSource, err = ensureGeodataFile(geoSitePath, []string{
		"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
		"https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
	})
	if err != nil {
		return "", "", err
	}

	if err := validateGeodataFiles(geoIPPath, geoSitePath); err != nil {
		return "", "", err
	}
	return geoIPSource, geoSiteSource, nil
}

func ensureGeodataFile(path string, sources []string) (string, error) {
	p := strings.TrimSpace(path)
	if p == "" {
		return "", fmt.Errorf("empty geodata path")
	}

	dir := filepath.Dir(p)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create geodata directory %q: %w", dir, err)
	}

	if err := assertReadableFile(p); err == nil {
		return "existing", nil
	}

	var lastErr error
	for _, source := range sources {
		src := strings.TrimSpace(source)
		if src == "" {
			continue
		}
		if err := downloadFileToPath(src, p); err != nil {
			lastErr = err
			continue
		}
		if err := assertReadableFile(p); err != nil {
			lastErr = err
			continue
		}
		return src, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no valid geodata source configured")
	}
	return "", fmt.Errorf("prepare geodata file %q: %w", p, lastErr)
}

func downloadFileToPath(source, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return fmt.Errorf("build request %q: %w", source, err)
	}
	req.Header.Set("User-Agent", "hivoid-core/hub-geodata-installer")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download %q: %w", source, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download %q: unexpected status %s", source, resp.Status)
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create temp file %q: %w", tmpPath, err)
	}

	written, copyErr := io.Copy(tmpFile, resp.Body)
	closeErr := tmpFile.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp file %q: %w", tmpPath, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file %q: %w", tmpPath, closeErr)
	}
	if written <= 0 {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("download %q produced empty file", source)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace %q with downloaded file: %w", path, err)
	}
	return nil
}

func assertReadableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%q is a directory", path)
	}
	if info.Size() <= 0 {
		return fmt.Errorf("%q is empty", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 1)
	if _, err := f.Read(buf); err != nil {
		return err
	}
	return nil
}

func validateGeodataFiles(geoIPPath, geoSitePath string) error {
	if err := assertReadableFile(geoIPPath); err != nil {
		return fmt.Errorf("geoip file not readable: %w", err)
	}
	if err := assertReadableFile(geoSitePath); err != nil {
		return fmt.Errorf("geosite file not readable: %w", err)
	}

	var domains []string
	var ipNets []*net.IPNet
	if err := geodata.LoadGeoData(geoIPPath, geoSitePath, []string{"ZZ"}, &domains, &ipNets); err != nil {
		return fmt.Errorf("geodata parse validation failed: %w", err)
	}
	return nil
}

func decodeTLSInstallRequest(msg HubMessage) hubTLSInstallRequest {
	req := hubTLSInstallRequest{
		Type:               strings.TrimSpace(msg.InstallType),
		Domain:             strings.TrimSpace(msg.Domain),
		Email:              strings.TrimSpace(msg.Email),
		CloudflareAPIToken: strings.TrimSpace(msg.CloudflareAPIToken),
		CertFile:           strings.TrimSpace(msg.CertFile),
		KeyFile:            strings.TrimSpace(msg.KeyFile),
	}
	for _, raw := range commandPayloadCandidates(msg.TLS, msg.Payload, msg.Data, msg.Config) {
		var p hubTLSInstallRequest
		if !decodeRaw(raw, &p) {
			continue
		}
		if strings.TrimSpace(p.Type) != "" {
			req.Type = strings.TrimSpace(p.Type)
		}
		if strings.TrimSpace(p.Domain) != "" {
			req.Domain = strings.TrimSpace(p.Domain)
		}
		if strings.TrimSpace(p.Email) != "" {
			req.Email = strings.TrimSpace(p.Email)
		}
		if strings.TrimSpace(p.CloudflareAPIToken) != "" {
			req.CloudflareAPIToken = strings.TrimSpace(p.CloudflareAPIToken)
		}
		if strings.TrimSpace(p.CertFile) != "" {
			req.CertFile = strings.TrimSpace(p.CertFile)
		}
		if strings.TrimSpace(p.KeyFile) != "" {
			req.KeyFile = strings.TrimSpace(p.KeyFile)
		}
	}
	return req
}

func decodeTLSSyncPathsRequest(msg HubMessage) hubTLSSyncPathsRequest {
	req := hubTLSSyncPathsRequest{
		Domain:   strings.TrimSpace(msg.Domain),
		CertFile: strings.TrimSpace(msg.CertFile),
		KeyFile:  strings.TrimSpace(msg.KeyFile),
	}
	for _, raw := range commandPayloadCandidates(msg.TLS, msg.Payload, msg.Data, msg.Config) {
		var p hubTLSSyncPathsRequest
		if !decodeRaw(raw, &p) {
			continue
		}
		if strings.TrimSpace(p.Domain) != "" {
			req.Domain = strings.TrimSpace(p.Domain)
		}
		if strings.TrimSpace(p.CertFile) != "" {
			req.CertFile = strings.TrimSpace(p.CertFile)
		}
		if strings.TrimSpace(p.KeyFile) != "" {
			req.KeyFile = strings.TrimSpace(p.KeyFile)
		}
	}
	return req
}

func decodeGeodataInstallRequest(msg HubMessage) hubGeodataInstallRequest {
	req := hubGeodataInstallRequest{
		GeoIPPath:   strings.TrimSpace(msg.GeoIPPath),
		GeoSitePath: strings.TrimSpace(msg.GeoSitePath),
	}
	for _, raw := range commandPayloadCandidates(msg.GeoData, msg.GeoDataLegacy, msg.Payload, msg.Data, msg.Config) {
		var p hubGeodataInstallRequest
		if !decodeRaw(raw, &p) {
			continue
		}
		if strings.TrimSpace(p.GeoIPPath) != "" {
			req.GeoIPPath = strings.TrimSpace(p.GeoIPPath)
		}
		if strings.TrimSpace(p.GeoSitePath) != "" {
			req.GeoSitePath = strings.TrimSpace(p.GeoSitePath)
		}
	}
	return req
}

func decodeRaw(raw json.RawMessage, out any) bool {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return false
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false
	}
	return true
}

func commandPayloadCandidates(raws ...json.RawMessage) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(raws)*3)
	seen := make(map[string]struct{}, len(raws)*3)

	add := func(raw json.RawMessage) {
		s := strings.TrimSpace(string(raw))
		if s == "" || s == "null" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, raw)
	}

	for _, raw := range raws {
		add(raw)
		var wrapper struct {
			Payload       json.RawMessage `json:"payload"`
			Data          json.RawMessage `json:"data"`
			Config        json.RawMessage `json:"config"`
			TLS           json.RawMessage `json:"tls"`
			GeoData       json.RawMessage `json:"geodata"`
			GeoDataLegacy json.RawMessage `json:"geo_data"`
		}
		if !decodeRaw(raw, &wrapper) {
			continue
		}
		add(wrapper.Payload)
		add(wrapper.Data)
		add(wrapper.Config)
		add(wrapper.TLS)
		add(wrapper.GeoData)
		add(wrapper.GeoDataLegacy)
	}

	return out
}

func looksLikeConfigPatch(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	if !decodeRaw(raw, &m) {
		return false
	}
	if len(m) == 0 {
		return false
	}
	for _, key := range []string{
		"server", "security", "features", "port", "name", "obfs", "cert", "cert_file", "key", "key_file",
		"mode", "server_mode", "max_conns", "allowed_hosts", "blocked_hosts", "blocked_tags", "anti_probe",
		"fallback_addr", "geoip_path", "geosite_path", "users", "listen_addr", "log_level", "connection_tracking",
		"disconnect_expired", "tls", "geodata", "geo_data",
	} {
		if _, ok := m[key]; ok {
			return true
		}
	}
	return false
}

func resolveNodeDomain(raw string, h *HubClient) string {
	domain := strings.TrimSpace(raw)
	if domain != "" {
		return domain
	}

	runtimeCfg := h.getRuntimeConfig()
	if runtimeCfg != nil {
		name := strings.TrimSpace(runtimeCfg.Name)
		if strings.Contains(name, ".") {
			return name
		}
	}

	u, err := url.Parse(h.cfg.Endpoint)
	if err != nil {
		return ""
	}
	host := strings.TrimSpace(u.Hostname())
	if strings.Contains(host, ".") {
		return host
	}
	return ""
}

func normalizeHubWebSocketPaths(rawPath string) []string {
	p := strings.TrimSpace(rawPath)
	if p == "" {
		return []string{"/api/v1/nodes/ws", "/api/v1/node/ws"}
	}
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if p != "/" {
		p = strings.TrimSuffix(p, "/")
	}

	switch p {
	case "", "/", "/api/v1", "/api/v1/node", "/api/v1/nodes":
		return []string{"/api/v1/nodes/ws", "/api/v1/node/ws"}
	case "/api/v1/nodes/ws":
		return []string{"/api/v1/nodes/ws", "/api/v1/node/ws"}
	case "/api/v1/node/ws":
		return []string{"/api/v1/node/ws", "/api/v1/nodes/ws"}
	default:
		return []string{p}
	}
}

func letsEncryptPaths(domain string) (certFile, keyFile string) {
	base := filepath.Join("/etc/letsencrypt/live", domain)
	return filepath.Join(base, "fullchain.pem"), filepath.Join(base, "privkey.pem")
}

func installOpenSSLCert(domain string) (certFile, keyFile string, err error) {
	certFile, keyFile = letsEncryptPaths(domain)
	if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
		return "", "", fmt.Errorf("create cert directory: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx,
		"openssl", "req",
		"-x509", "-newkey", "rsa:2048",
		"-sha256", "-nodes",
		"-keyout", keyFile,
		"-out", certFile,
		"-days", "365",
		"-subj", "/CN="+domain,
	)
	if out, cmdErr := cmd.CombinedOutput(); cmdErr != nil {
		return "", "", fmt.Errorf("openssl req failed: %w (%s)", cmdErr, strings.TrimSpace(string(out)))
	}
	return certFile, keyFile, nil
}

func installCloudflareCert(domain, email, token string) (certFile, keyFile string, err error) {
	if token == "" {
		return "", "", fmt.Errorf("cloudflare api token is required")
	}
	if email == "" {
		email = "admin@" + domain
	}

	tmpDir, err := os.MkdirTemp("", "hivoid-cloudflare-")
	if err != nil {
		return "", "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	credPath := filepath.Join(tmpDir, "cloudflare.ini")
	credContent := "dns_cloudflare_api_token = " + token + "\n"
	if err := os.WriteFile(credPath, []byte(credContent), 0600); err != nil {
		return "", "", fmt.Errorf("write cloudflare credentials: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx,
		"certbot", "certonly",
		"--dns-cloudflare",
		"--dns-cloudflare-credentials", credPath,
		"-d", domain,
		"--agree-tos",
		"-m", email,
		"--non-interactive",
	)
	if out, cmdErr := cmd.CombinedOutput(); cmdErr != nil {
		return "", "", fmt.Errorf("certbot failed: %w (%s)", cmdErr, strings.TrimSpace(string(out)))
	}

	certFile, keyFile = letsEncryptPaths(domain)
	if !fileExists(certFile) || !fileExists(keyFile) {
		return "", "", fmt.Errorf("certbot finished but certificate files were not found")
	}
	return certFile, keyFile, nil
}

func nodeAutoinstallEnabled() bool {
	if raw := strings.TrimSpace(os.Getenv("HIVOID_DISABLE_NODE_INSTALL")); raw != "" {
		if parsed, ok := parseEnvBool(raw); ok {
			return !parsed
		}
	}

	// Backward compatibility: if the old env is explicitly set, respect it.
	if raw := strings.TrimSpace(os.Getenv("HIVOID_ENABLE_NODE_INSTALL")); raw != "" {
		if parsed, ok := parseEnvBool(raw); ok {
			return parsed
		}
	}

	// Default behavior is enabled so Hub can manage install flows end-to-end.
	return true
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func parseEnvBool(raw string) (bool, bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}

func fallbackMissingTLSForConfigUpdate(nextCfg, prevCfg *config.ServerConfig, logger *zap.Logger) {
	if nextCfg == nil || prevCfg == nil {
		return
	}

	nextCert := strings.TrimSpace(nextCfg.Cert)
	nextKey := strings.TrimSpace(nextCfg.Key)
	prevCert := strings.TrimSpace(prevCfg.Cert)
	prevKey := strings.TrimSpace(prevCfg.Key)

	if nextCert != prevCert && !fileExists(nextCert) && fileExists(prevCert) {
		logger.Warn("hub config update references missing cert file; keeping previous cert path",
			zap.String("requested_cert", nextCert),
			zap.String("kept_cert", prevCert),
		)
		nextCfg.Cert = prevCert
	}

	if nextKey != prevKey && !fileExists(nextKey) && fileExists(prevKey) {
		logger.Warn("hub config update references missing key file; keeping previous key path",
			zap.String("requested_key", nextKey),
			zap.String("kept_key", prevKey),
		)
		nextCfg.Key = prevKey
	}
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "" {
			continue
		}
		k := strings.ToLower(v)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (h *HubClient) buildConfigUpdate(rawConfig json.RawMessage) (*config.ServerConfig, *hubConfigPatch, error) {
	base := h.getRuntimeConfig()
	if base == nil {
		base = defaultRuntimeConfig()
	}
	next := cloneServerConfig(base)

	var patch hubConfigPatch
	if err := json.Unmarshal(rawConfig, &patch); err != nil {
		return nil, nil, err
	}

	if len(patch.Server) > 0 {
		if err := applyServerPatch(next, patch.Server); err != nil {
			return nil, nil, err
		}
	}
	if len(patch.Security) > 0 {
		var sec struct {
			CertFile string `json:"cert_file"`
			KeyFile  string `json:"key_file"`
		}
		if err := json.Unmarshal(patch.Security, &sec); err != nil {
			return nil, nil, fmt.Errorf("security: %w", err)
		}
		if strings.TrimSpace(sec.CertFile) != "" {
			next.Cert = strings.TrimSpace(sec.CertFile)
		}
		if strings.TrimSpace(sec.KeyFile) != "" {
			next.Key = strings.TrimSpace(sec.KeyFile)
		}
	}
	for _, tlsRaw := range []json.RawMessage{patch.TLS} {
		if len(tlsRaw) == 0 {
			continue
		}
		var tlsPatch struct {
			CertFile string `json:"cert_file"`
			KeyFile  string `json:"key_file"`
		}
		if err := json.Unmarshal(tlsRaw, &tlsPatch); err != nil {
			return nil, nil, fmt.Errorf("tls: %w", err)
		}
		if strings.TrimSpace(tlsPatch.CertFile) != "" {
			next.Cert = strings.TrimSpace(tlsPatch.CertFile)
		}
		if strings.TrimSpace(tlsPatch.KeyFile) != "" {
			next.Key = strings.TrimSpace(tlsPatch.KeyFile)
		}
	}
	for _, geodataRaw := range []json.RawMessage{patch.GeoData, patch.GeoDataLegacy} {
		if len(geodataRaw) == 0 {
			continue
		}
		var geoPatch struct {
			GeoIPPath   string `json:"geoip_path"`
			GeoSitePath string `json:"geosite_path"`
		}
		if err := json.Unmarshal(geodataRaw, &geoPatch); err != nil {
			return nil, nil, fmt.Errorf("geodata: %w", err)
		}
		if strings.TrimSpace(geoPatch.GeoIPPath) != "" {
			next.GeoIPPath = strings.TrimSpace(geoPatch.GeoIPPath)
		}
		if strings.TrimSpace(geoPatch.GeoSitePath) != "" {
			next.GeoSitePath = strings.TrimSpace(geoPatch.GeoSitePath)
		}
	}
	if len(patch.Features) > 0 {
		var feats struct {
			HotReload          bool `json:"hot_reload"`
			ConnectionTracking bool `json:"connection_tracking"`
			DisconnectExpired  bool `json:"disconnect_expired"`
		}
		if err := json.Unmarshal(patch.Features, &feats); err != nil {
			return nil, nil, fmt.Errorf("features: %w", err)
		}
		next.HotReload = feats.HotReload
		next.ConnectionTracking = feats.ConnectionTracking
		next.DisconnectExpired = feats.DisconnectExpired
	}
	if patch.ListenAddr != nil {
		host, port, err := parseListenAddr(*patch.ListenAddr, next.Server)
		if err != nil {
			return nil, nil, fmt.Errorf("listen_addr: %w", err)
		}
		next.Server = host
		next.Port = port
	}

	if patch.Port != nil && *patch.Port > 0 {
		next.Port = *patch.Port
	}
	if patch.Name != nil {
		next.Name = strings.TrimSpace(*patch.Name)
	}
	if patch.Obfs != nil {
		next.Obfs = strings.TrimSpace(*patch.Obfs)
	}
	if patch.Cert != nil {
		next.Cert = strings.TrimSpace(*patch.Cert)
	}
	if patch.CertFile != nil {
		next.Cert = strings.TrimSpace(*patch.CertFile)
	}
	if patch.Key != nil {
		next.Key = strings.TrimSpace(*patch.Key)
	}
	if patch.KeyFile != nil {
		next.Key = strings.TrimSpace(*patch.KeyFile)
	}
	if patch.Mode != nil {
		next.Mode = strings.TrimSpace(*patch.Mode)
	}
	if patch.ServerMode != nil {
		next.Mode = strings.TrimSpace(*patch.ServerMode)
	}
	if patch.LogLevel != nil {
		next.LogLevel = strings.TrimSpace(*patch.LogLevel)
	}
	if patch.HotReload != nil {
		next.HotReload = *patch.HotReload
	}
	if patch.ConnectionTracking != nil {
		next.ConnectionTracking = *patch.ConnectionTracking
	}
	if patch.DisconnectExpired != nil {
		next.DisconnectExpired = *patch.DisconnectExpired
	}
	if patch.MaxConns != nil {
		if *patch.MaxConns < 0 {
			next.MaxConns = 0
		} else {
			next.MaxConns = *patch.MaxConns
		}
	}
	if patch.AntiProbe != nil {
		next.AntiProbe = *patch.AntiProbe
	}
	if patch.FallbackAddr != nil {
		next.FallbackAddr = strings.TrimSpace(*patch.FallbackAddr)
	}
	if patch.GeoIPPath != nil {
		next.GeoIPPath = strings.TrimSpace(*patch.GeoIPPath)
	}
	if patch.GeoSitePath != nil {
		next.GeoSitePath = strings.TrimSpace(*patch.GeoSitePath)
	}
	if patch.AllowedHosts != nil {
		next.AllowedHosts = append([]string(nil), (*patch.AllowedHosts)...)
	}
	if patch.BlockedHosts != nil {
		next.BlockedHosts = append([]string(nil), (*patch.BlockedHosts)...)
	}
	if patch.BlockedTags != nil {
		next.BlockedTags = append([]string(nil), (*patch.BlockedTags)...)
	}
	if patch.Users != nil {
		next.Users = append([]config.ServerUserConfig(nil), (*patch.Users)...)
	}

	normalizeRuntimeConfig(next)
	return next, &patch, nil
}

func normalizeRuntimeConfig(c *config.ServerConfig) {
	if c == nil {
		return
	}
	if strings.TrimSpace(c.Server) == "" {
		c.Server = "0.0.0.0"
	}
	if c.Port <= 0 {
		c.Port = 4433
	}
	if strings.TrimSpace(c.Mode) == "" {
		c.Mode = config.DefaultMode
	}
	if strings.TrimSpace(c.Obfs) == "" {
		c.Obfs = config.DefaultObfs
	}
}

func defaultRuntimeConfig() *config.ServerConfig {
	return &config.ServerConfig{
		Server:    "0.0.0.0",
		Port:      4433,
		Cert:      "cert.pem",
		Key:       "key.pem",
		Mode:      config.DefaultMode,
		Obfs:      config.DefaultObfs,
		AntiProbe: true,
	}
}

func cloneServerConfig(in *config.ServerConfig) *config.ServerConfig {
	if in == nil {
		return nil
	}
	out := *in
	out.AllowedHosts = append([]string(nil), in.AllowedHosts...)
	out.BlockedHosts = append([]string(nil), in.BlockedHosts...)
	out.AllowedUUIDs = append([]string(nil), in.AllowedUUIDs...)
	out.BlockedTags = append([]string(nil), in.BlockedTags...)
	out.Users = make([]config.ServerUserConfig, len(in.Users))
	for i := range in.Users {
		out.Users[i] = in.Users[i]
		out.Users[i].BlockedHosts = append([]string(nil), in.Users[i].BlockedHosts...)
		out.Users[i].BlockedTags = append([]string(nil), in.Users[i].BlockedTags...)
	}
	return &out
}

func applyServerPatch(dst *config.ServerConfig, raw json.RawMessage) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil
	}

	var host string
	if err := json.Unmarshal(raw, &host); err == nil {
		host = strings.TrimSpace(host)
		if host != "" {
			dst.Server = host
		}
		return nil
	}

	var section struct {
		Listen   string `json:"listen"`
		Mode     string `json:"mode"`
		LogLevel string `json:"log_level"`
	}
	if err := json.Unmarshal(raw, &section); err != nil {
		return fmt.Errorf("invalid server patch: %w", err)
	}
	if section.Listen != "" {
		host, port, err := parseListenAddr(section.Listen, dst.Server)
		if err != nil {
			return err
		}
		dst.Server = host
		dst.Port = port
	}
	if strings.TrimSpace(section.Mode) != "" {
		dst.Mode = strings.TrimSpace(section.Mode)
	}
	if strings.TrimSpace(section.LogLevel) != "" {
		dst.LogLevel = strings.TrimSpace(section.LogLevel)
	}
	return nil
}

func parseListenAddr(raw string, fallbackHost string) (string, int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0, fmt.Errorf("empty listen address")
	}

	if strings.HasPrefix(s, ":") {
		p, err := strconv.Atoi(strings.TrimPrefix(s, ":"))
		if err != nil || p < 1 || p > 65535 {
			return "", 0, fmt.Errorf("invalid port in listen address %q", raw)
		}
		host := strings.TrimSpace(fallbackHost)
		if host == "" {
			host = "0.0.0.0"
		}
		return host, p, nil
	}

	host, portStr, err := net.SplitHostPort(s)
	if err == nil {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return "", 0, fmt.Errorf("invalid port in listen address %q", raw)
		}
		if strings.TrimSpace(host) == "" {
			host = "0.0.0.0"
		}
		return host, p, nil
	}

	i := strings.LastIndex(s, ":")
	if i <= 0 || i >= len(s)-1 {
		return "", 0, fmt.Errorf("invalid listen address %q", raw)
	}
	h := strings.TrimSpace(s[:i])
	if strings.Contains(h, ":") {
		return "", 0, fmt.Errorf("invalid listen address %q", raw)
	}
	p, err := strconv.Atoi(strings.TrimSpace(s[i+1:]))
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("invalid port in listen address %q", raw)
	}
	return h, p, nil
}

func (h *HubClient) getRuntimeConfig() *config.ServerConfig {
	h.runtimeMu.RLock()
	defer h.runtimeMu.RUnlock()
	return cloneServerConfig(h.runtimeCfg)
}

func (h *HubClient) setRuntimeConfig(c *config.ServerConfig) {
	h.runtimeMu.Lock()
	defer h.runtimeMu.Unlock()
	h.runtimeCfg = cloneServerConfig(c)
}

func (h *HubClient) currentNodeID() string {
	cfg := h.getRuntimeConfig()
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.Name)
}

func (h *HubClient) telemetryLoop(conn *websocket.Conn) {
	interval := time.Duration(h.cfg.SyncIntervalMs) * time.Millisecond
	if interval < 1000*time.Millisecond {
		interval = 3 * time.Second // Enforce minimum 3s protection to avoid flooding
	}
	reportInterval := 5 * time.Minute

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	reportTicker := time.NewTicker(reportInterval)
	defer reportTicker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-reportTicker.C:
			if err := h.sendNodeReport(); err != nil {
				h.logger.Error("failed to send REPORT to hub", zap.Error(err))
				_ = conn.Close()
				return
			}
		case <-ticker.C:
			// Fetch live snapshots and include offline transitions (request_pool=0)
			var snapshots []session.SessionSnapshot
			if h.manager != nil {
				snapshots = h.manager.GetActiveSnapshots()
			}
			usageList := h.buildUsageBatch(snapshots)
			usageList = h.mergeUsageWithOfflineTransitions(usageList)

			if len(usageList) > 0 {
				msg := HubMessage{
					Type:  "USAGE",
					Usage: usageList,
				}

				h.mu.Lock()
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				err := conn.WriteJSON(msg)
				h.mu.Unlock()

				if err != nil {
					h.logger.Error("failed to send telemetry to hub", zap.Error(err))
					_ = conn.Close()
					return
				}
			}
		}
	}
}

func (h *HubClient) buildUsageBatch(snapshots []session.SessionSnapshot) []HubUserUsage {
	if len(snapshots) == 0 {
		return nil
	}

	usageMap := make(map[[16]byte]*HubUserUsage, len(snapshots))
	order := make([][16]byte, 0, len(snapshots))

	for _, snap := range snapshots {
		uuid, err := parseUUID(snap.UUID)
		if err != nil {
			continue
		}

		snapConnectedAt := normalizeTelemetryConnectedAt(snap.StartTime)
		snapSrcIP := normalizeTelemetrySrcIP(snap.RemoteAddr)

		u, ok := usageMap[uuid]
		if !ok {
			baselineIn, baselineOut := uint64(0), uint64(0)
			if h.usrCtrls != nil {
				baselineIn, baselineOut = h.usrCtrls.UserUsage(uuid)
			}

			usage := &HubUserUsage{
				UUID:        snap.UUID,
				BytesIn:     baselineIn,
				BytesOut:    baselineOut,
				ConnectedAt: snapConnectedAt,
				SrcIP:       snapSrcIP,
			}
			if h.manager != nil {
				if p, hasPolicy := h.manager.GetPolicy(uuid); hasPolicy {
					usage.Email = p.Email
					usage.DataLimit = p.DataLimit
					usage.MaxIPs = p.MaxIPs
					usage.MaxConnections = p.MaxConnections
					usage.BlockedHosts = append([]string(nil), p.BlockedHosts...)
					usage.BlockedTags = append([]string(nil), p.BlockedTags...)
				}
			}

			usageMap[uuid] = usage
			order = append(order, uuid)
			u = usage
		}

		u.BytesIn += snap.TrafficIn
		u.BytesOut += snap.TrafficOut
		u.RequestPool += snap.ConnCount

		if u.ConnectedAt <= 0 || (snapConnectedAt > 0 && snapConnectedAt < u.ConnectedAt) {
			u.ConnectedAt = snapConnectedAt
			u.SrcIP = snapSrcIP
		} else if !isTelemetrySrcIPKnown(u.SrcIP) && isTelemetrySrcIPKnown(snapSrcIP) {
			u.SrcIP = snapSrcIP
		}
	}

	usageList := make([]HubUserUsage, 0, len(order))
	for _, uuid := range order {
		if item, ok := usageMap[uuid]; ok {
			usageList = append(usageList, *item)
		}
	}

	return usageList
}

func (h *HubClient) mergeUsageWithOfflineTransitions(active []HubUserUsage) []HubUserUsage {
	current := make(map[[16]byte]HubUserUsage, len(active))
	merged := make([]HubUserUsage, 0, len(active))

	for _, item := range active {
		uuid, err := parseUUID(item.UUID)
		if err != nil {
			continue
		}
		cloned := cloneHubUserUsage(item)
		current[uuid] = cloned
		merged = append(merged, cloned)
	}

	h.usageMu.Lock()
	defer h.usageMu.Unlock()

	for uuid, prev := range h.lastOnline {
		if _, stillOnline := current[uuid]; stillOnline {
			continue
		}
		offline := cloneHubUserUsage(prev)
		offline.RequestPool = 0
		if h.usrCtrls != nil {
			offline.BytesIn, offline.BytesOut = h.usrCtrls.UserUsage(uuid)
		}
		if offline.SrcIP == "" {
			offline.SrcIP = "unknown"
		}
		merged = append(merged, offline)
	}

	next := make(map[[16]byte]HubUserUsage, len(current))
	for uuid, usage := range current {
		next[uuid] = cloneHubUserUsage(usage)
	}
	h.lastOnline = next

	return merged
}

func cloneHubUserUsage(in HubUserUsage) HubUserUsage {
	out := in
	out.BlockedHosts = append([]string(nil), in.BlockedHosts...)
	out.BlockedTags = append([]string(nil), in.BlockedTags...)
	return out
}

func normalizeTelemetryConnectedAt(start time.Time) int64 {
	if start.IsZero() {
		return time.Now().Unix()
	}
	unix := start.Unix()
	if unix <= 0 {
		return time.Now().Unix()
	}
	return unix
}

func normalizeTelemetrySrcIP(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(v); err == nil {
		h := strings.TrimSpace(host)
		if h != "" {
			return h
		}
	}
	v = strings.Trim(v, "[]")
	if v == "" {
		return "unknown"
	}
	return v
}

func isTelemetrySrcIPKnown(ip string) bool {
	v := strings.TrimSpace(strings.ToLower(ip))
	return v != "" && v != "unknown"
}

func (h *HubClient) sendNodeReport() error {
	report := h.buildNodeReportMessage()
	if err := h.writeHubJSON(report); err != nil {
		return err
	}
	h.logger.Debug("REPORT sent",
		zap.String("cert_pin", report.CertPin),
		zap.String("cert_expires_at", report.CertExpiresAt),
		zap.Int("active_connections", report.Stats.ActiveConnections),
	)
	return nil
}

func (h *HubClient) buildNodeReportMessage() hubReportMessage {
	processCPUPct := h.sampleProcessCPUPercent()
	var procMem runtime.MemStats
	runtime.ReadMemStats(&procMem)
	processRAMMB := float64(procMem.Alloc) / (1024.0 * 1024.0)

	systemCPUPct, systemRAMPct, systemRAMUsedBytes, systemRAMTotalBytes := sampleSystemMetrics()
	rootCPU := processCPUPct
	if systemCPUPct > 0 {
		rootCPU = systemCPUPct
	}
	rootRAM := systemRAMPct
	rootRAMMB := processRAMMB
	if systemRAMUsedBytes > 0 {
		rootRAMMB = float64(systemRAMUsedBytes) / (1024.0 * 1024.0)
	}
	if rootRAM < 0 {
		rootRAM = 0
	}
	if rootRAM > 100 {
		rootRAM = 100
	}

	uptimeSeconds := int64(time.Since(h.startTime).Seconds())
	if uptimeSeconds < 0 {
		uptimeSeconds = 0
	}
	connectedAt := ""
	if !h.startTime.IsZero() {
		connectedAt = h.startTime.UTC().Format(time.RFC3339)
	}
	reportedAt := time.Now().UTC().Format(time.RFC3339)

	report := hubReportMessage{
		Type:               "REPORT",
		ConnectedAt:        connectedAt,
		ReportedAt:         reportedAt,
		ReportIntervalMS:   h.reportIntervalMS(),
		CPUUsage:           clampPercent(rootCPU),
		RAMUsage:           clampPercent(rootRAM),
		RAMUsageMB:         rootRAMMB,
		Uptime:             formatUptimeHuman(uptimeSeconds),
		UptimeSeconds:      uptimeSeconds,
		ProcessCPUUsage:    clampPercent(processCPUPct),
		ProcessRAMUsageMB:  processRAMMB,
		ProcessRAMUsageB:   procMem.Alloc,
		SystemCPUUsage:     clampPercent(systemCPUPct),
		SystemRAMUsage:     clampPercent(systemRAMPct),
		SystemRAMUsageMB:   float64(systemRAMUsedBytes) / (1024.0 * 1024.0),
		SystemRAMTotalMB:   float64(systemRAMTotalBytes) / (1024.0 * 1024.0),
		SystemRAMUsedBytes: systemRAMUsedBytes,
		SystemRAMTotBytes:  systemRAMTotalBytes,
		Stats: hubReportStats{
			ActiveConnections:    0,
			CPUPercent:           clampPercent(processCPUPct),
			MemoryPercent:        clampPercent(systemRAMPct),
			UptimeSeconds:        uptimeSeconds,
			MemoryBytes:          procMem.Alloc,
			ProcessCPUPercent:    clampPercent(processCPUPct),
			ProcessMemoryBytes:   procMem.Alloc,
			SystemCPUPercent:     clampPercent(systemCPUPct),
			SystemMemoryPercent:  clampPercent(systemRAMPct),
			SystemMemoryUsedByte: systemRAMUsedBytes,
			SystemMemoryTotByte:  systemRAMTotalBytes,
		},
	}
	if h.manager != nil {
		report.Stats.ActiveConnections = h.manager.Count()
	}

	runtimeCfg := h.getRuntimeConfig()
	if runtimeCfg == nil {
		return report
	}
	certPath := strings.TrimSpace(runtimeCfg.Cert)
	if certPath == "" {
		return report
	}

	pin, expiresAt, err := certPinFromPEMFile(certPath)
	if err != nil {
		h.logger.Warn("failed to calculate cert pin for REPORT", zap.String("cert_file", certPath), zap.Error(err))
		return report
	}
	report.CertPin = pin
	report.CertExpiresAt = expiresAt
	return report
}

func (h *HubClient) reportIntervalMS() int {
	intervalMS := h.cfg.SyncIntervalMs
	if intervalMS < 3000 {
		intervalMS = 3000
	}
	return intervalMS
}

func formatUptimeHuman(totalSeconds int64) string {
	if totalSeconds < 0 {
		totalSeconds = 0
	}

	days := totalSeconds / 86400
	hours := (totalSeconds % 86400) / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%ds", seconds)
}

func (h *HubClient) sampleProcessCPUPercent() float64 {
	samples := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(samples)
	if len(samples) == 0 || samples[0].Value.Kind() != metrics.KindFloat64 {
		return 0
	}

	now := time.Now()
	curr := samples[0].Value.Float64()

	h.cpuMu.Lock()
	defer h.cpuMu.Unlock()

	if !h.hasCPUSample {
		h.lastCPUSample = curr
		h.lastCPUAt = now
		h.hasCPUSample = true
		return 0
	}

	deltaCPU := curr - h.lastCPUSample
	deltaTime := now.Sub(h.lastCPUAt).Seconds()
	h.lastCPUSample = curr
	h.lastCPUAt = now

	if deltaCPU <= 0 || deltaTime <= 0 {
		return 0
	}

	cpuCount := float64(runtime.NumCPU())
	if cpuCount <= 0 {
		cpuCount = 1
	}
	pct := (deltaCPU / (deltaTime * cpuCount)) * 100.0
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

func sampleSystemMetrics() (cpuPercent float64, ramPercent float64, ramUsedBytes uint64, ramTotalBytes uint64) {
	cpuValues, cpuErr := gopsutilcpu.Percent(0, false)
	if cpuErr == nil && len(cpuValues) > 0 {
		cpuPercent = clampPercent(cpuValues[0])
	}

	vMem, memErr := gopsutilmem.VirtualMemory()
	if memErr == nil && vMem != nil {
		ramPercent = clampPercent(vMem.UsedPercent)
		ramUsedBytes = vMem.Used
		ramTotalBytes = vMem.Total
	}

	return cpuPercent, ramPercent, ramUsedBytes, ramTotalBytes
}

func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func certPinFromPEMFile(certPath string) (pin string, expiresAt string, err error) {
	path := strings.TrimSpace(certPath)
	if path == "" {
		return "", "", fmt.Errorf("empty cert path")
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read cert file %q: %w", path, err)
	}

	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			continue
		}
		sum := sha256.Sum256(cert.Raw)
		return "sha256:" + hex.EncodeToString(sum[:]), cert.NotAfter.UTC().Format(time.RFC3339), nil
	}

	return "", "", fmt.Errorf("no valid certificate block found in %q", path)
}

func normalizeCertPin(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "sha256:") {
		hexPart := strings.TrimPrefix(v, "sha256:")
		if len(hexPart) == 64 && isHexString(hexPart) {
			return "sha256:" + hexPart
		}
		return v
	}
	if len(v) == 64 && isHexString(v) {
		return "sha256:" + v
	}
	return v
}

func isHexString(raw string) bool {
	if raw == "" {
		return false
	}
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}
