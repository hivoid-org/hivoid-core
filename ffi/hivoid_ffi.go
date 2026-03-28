package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/hivoid-org/hivoid-core/client"
	"github.com/hivoid-org/hivoid-core/config"
	"github.com/hivoid-org/hivoid-core/intelligence"
	"github.com/hivoid-org/hivoid-core/session"
	"github.com/hivoid-org/hivoid-core/transport"
	"github.com/hivoid-org/hivoid-core/utils"
	"go.uber.org/zap"
)

var (
	mu               sync.Mutex
	isRunning        bool
	cancelFunc       context.CancelFunc
	hvClient         *transport.Client
	currentSess      *session.Session
	startTime        time.Time
	lastError        error
	protectCallCount uint64
	currentSocksPort int
	currentDNSPort   int

	statsMu      sync.Mutex
	lastSent     uint64
	lastRecv     uint64
	lastStatTime time.Time
)

const protectSocketName = "hivoid_protect"

func InternalProtectSocket(fd int) {
	atomic.AddUint64(&protectCallCount, 1)
	conn, err := net.DialTimeout("unix", "\x00"+protectSocketName, 2*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(fd))
	conn.Write(buf)
	resp := make([]byte, 1)
	conn.Read(resp)
}

func onSocketCreated(fd int) { InternalProtectSocket(fd) }

// --- FFI EXPORTS ---

//export Start
func Start(configStr *C.char) *C.char {
	alog("HiVoidFFI", "Start() called")
	mu.Lock()
	defer mu.Unlock()
	if isRunning {
		return C.CString("HiVoid is already running")
	}
	cfg, err := parseConfig(C.GoString(configStr))
	if err != nil {
		return C.CString(fmt.Sprintf("config error: %v", err))
	}
	if cfg.DNSPort == 0 {
		cfg.DNSPort = 10853
	}
	currentSocksPort = cfg.SocksPort
	currentDNSPort = cfg.DNSPort
	alog("HiVoidFFI", fmt.Sprintf("Start: socks=%d dns=%d", cfg.SocksPort, cfg.DNSPort))
	return startCore(cfg)
}


//export GetSOCKSPort
func GetSOCKSPort() C.int { return C.int(1080) }

//export GetDNSPort
func GetDNSPort() C.int { return C.int(10853) }

//export GetTrafficStats
func GetTrafficStats() *C.char {
	mu.Lock()
	sess := currentSess
	mu.Unlock()

	var totalSent, totalRecv uint64
	if sess != nil {
		totalSent, totalRecv = sess.GetTrafficStats()
	}

	statsMu.Lock()
	defer statsMu.Unlock()

	now := time.Now()
	var upSpeed, downSpeed uint64

	if !lastStatTime.IsZero() {
		duration := now.Sub(lastStatTime).Seconds()
		if duration > 0.1 {
			if totalSent >= lastSent {
				upSpeed = uint64(float64(totalSent-lastSent) / duration)
			}
			if totalRecv >= lastRecv {
				downSpeed = uint64(float64(totalRecv-lastRecv) / duration)
			}
		}
	}

	lastSent = totalSent
	lastRecv = totalRecv
	lastStatTime = now

	stats := map[string]interface{}{
		"upload_speed":   upSpeed,
		"download_speed": downSpeed,
		"total_upload":   totalSent,
		"total_download": totalRecv,
	}

	data, _ := json.Marshal(stats)
	return C.CString(string(data))
}

//export TestLatency
func TestLatency() C.int {
	mu.Lock()
	sess := currentSess
	mu.Unlock()

	if sess == nil || sess.State() != session.StateActive {
		return -1
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := sess.DialTunnel(ctx, "www.google.com:80")
	if err != nil {
		return -1
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"))
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(buf)

	return C.int(time.Since(start).Milliseconds())
}

//export TestConfigLatency
func TestConfigLatency(configStr *C.char) C.int {
	cfg, err := parseConfig(C.GoString(configStr))
	if err != nil {
		return -1
	}

	logger, _ := utils.NewLogger(false)
	uuidBytes, _ := cfg.UUIDBytes()

	c := transport.NewClient(transport.ClientConfig{
		ServerAddr: cfg.ServerAddr(),
		Mode:       intelligence.ModeFromString(cfg.Mode),
		ObfsName:   cfg.Obfs,
		ObfsConfig: session.ObfsConfigForName(cfg.Obfs),
		Insecure:   cfg.Insecure,
		Logger:     logger,
		UUID:       uuidBytes,
	})
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	sess, err := c.Connect(ctx)
	if err != nil {
		return -1
	}
	defer sess.Close()

	conn, err := sess.DialTunnel(ctx, "www.google.com:80")
	if err != nil {
		return -1
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"))
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Read(buf)

	return C.int(time.Since(start).Milliseconds())
}

//export RegisterNativeProtect
func RegisterNativeProtect(ptr unsafe.Pointer) {
	alog("HiVoidFFI", "RegisterNativeProtect: no-op, using UDS")
}

//export ProtectFD
func ProtectFD(fd C.int) C.int {
	InternalProtectSocket(int(fd))
	return 1
}

//export Stop
func Stop() *C.char {
	alog("HiVoidFFI", "Stop() called")
	mu.Lock()
	defer mu.Unlock()
	if !isRunning {
		return nil
	}
	if cancelFunc != nil {
		cancelFunc()
		cancelFunc = nil
	}
	if hvClient != nil {
		hvClient.Close()
		hvClient = nil
	}
	isRunning = false
	currentSess = nil
	currentSocksPort = 0
	currentDNSPort = 0
	return nil
}

//export Status
func Status() *C.char {
	mu.Lock()
	defer mu.Unlock()

	status := map[string]interface{}{
		"running":       isRunning,
		"uptime":        0,
		"server":        "",
		"error":         "",
		"protect_calls": atomic.LoadUint64(&protectCallCount),
	}
	if lastError != nil {
		status["error"] = lastError.Error()
	}
	if isRunning {
		status["uptime"] = int64(time.Since(startTime).Seconds())
		if hvClient != nil {
			status["server"] = hvClient.Manager().Count()
		}
		if currentSess != nil && currentSess.State() == session.StateActive {
			if eng := safeGetEngine(currentSess); eng != nil {
				snap := eng.Metrics().Snapshot()
				status["session_id"] = currentSess.ID().String()
				status["rtt_ms"] = snap.RTT.Milliseconds()
				status["throughput_bps"] = snap.Throughput
				status["loss_rate"] = snap.PacketLoss
				status["mode"] = eng.ActiveMode().String()
			} else {
				status["state"] = "active"
			}
		} else {
			status["state"] = "connecting"
		}
	}
	data, _ := json.Marshal(status)
	return C.CString(string(data))
}

// --- INTERNAL ---

func startCore(cfg *config.Config) *C.char {
	logger, err := utils.NewLogger(false)
	if err != nil {
		return C.CString(fmt.Sprintf("logger error: %v", err))
	}
	utils.SetGlobalLogger(logger)

	uuidBytes, err := cfg.UUIDBytes()
	if err != nil {
		return C.CString(fmt.Sprintf("invalid uuid: %v", err))
	}

	hvClient = transport.NewClient(transport.ClientConfig{
		ServerAddr:    cfg.ServerAddr(),
		Mode:          intelligence.ModeFromString(cfg.Mode),
		ObfsName:      cfg.Obfs,
		ObfsConfig:    session.ObfsConfigForName(cfg.Obfs),
		Insecure:      cfg.Insecure,
		Logger:        logger,
		UUID:          uuidBytes,
		SocketControl: onSocketCreated,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancelFunc = cancel
	startTime = time.Now()
	isRunning = true
	lastError = nil

	// reset traffic stats
	statsMu.Lock()
	lastSent = 0
	lastRecv = 0
	lastStatTime = time.Time{}
	statsMu.Unlock()

	alog("HiVoidFFI", "startCore: core goroutine starting")
	go runCore(ctx, cfg, hvClient, logger)
	return nil
}

func parseConfig(s string) (*config.Config, error) {
	if strings.HasPrefix(s, "hivoid://") {
		return config.ParseURI(s)
	}
	var cfg config.Config
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	if cfg.Mode == "" { cfg.Mode = "adaptive" }
	if cfg.Obfs == "" { cfg.Obfs = "none" }
	if cfg.SocksPort == 0 { cfg.SocksPort = 1080 }
	if cfg.DNSUpstream == "" { cfg.DNSUpstream = "8.8.8.8:53" }
	if cfg.Name == "" { cfg.Name = "hivoid" }
	if cfg.DNSPort == 0 { cfg.DNSPort = 10853 }
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func safeGetEngine(s *session.Session) (result *intelligence.Engine) {
	defer func() {
		if r := recover(); r != nil { result = nil }
	}()
	val := reflect.ValueOf(s).Elem()
	field := val.FieldByName("engine")
	if !field.IsValid() { return nil }
	ptr := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	eng, ok := ptr.Interface().(*intelligence.Engine)
	if !ok || eng == nil { return nil }
	return eng
}

func runCore(ctx context.Context, cfg *config.Config, trClient *transport.Client, logger *zap.Logger) {
	defer func() {
		mu.Lock()
		isRunning = false
		mu.Unlock()
		alog("HiVoidFFI", "runCore: exited")
	}()

	if cfg.Obfs != "" && cfg.Obfs != "none" {
		trClient.Manager().SetObfuscation(session.ObfsConfigForName(cfg.Obfs))
		trClient.Manager().SetClientParams(intelligence.ModeFromString(cfg.Mode), cfg.Obfs)
	}

	alog("HiVoidFFI", "runCore: connecting...")
	sess, err := connectRetry(ctx, trClient, logger)
	if err != nil {
		mu.Lock()
		lastError = err
		mu.Unlock()
		alog("HiVoidFFI", "runCore: connect failed: "+err.Error())
		return
	}
	alog("HiVoidFFI", "runCore: connected!")
	mu.Lock()
	currentSess = sess
	mu.Unlock()

	bypassDomains := append([]string{}, cfg.BypassDomains...)
	parsedBypassIPs := client.ParseBypassIPStrings(cfg.BypassIPs, logger)
	if cfg.GeoIPPath != "" || cfg.GeoSitePath != "" {
		if len(cfg.DirectRoute) > 0 {
			if err := client.LoadGeoData(cfg.GeoIPPath, cfg.GeoSitePath, cfg.DirectRoute, &bypassDomains, &parsedBypassIPs); err != nil {
				alog("HiVoidFFI", "geodata load failed: "+err.Error())
			}
		}
	}

	dialTunnel := func(dialCtx context.Context, target string, udp bool) (net.Conn, error) {
		mu.Lock()
		s := currentSess
		mu.Unlock()
		if s == nil || s.State() != session.StateActive {
			next, err := connectRetry(dialCtx, trClient, logger)
			if err != nil { return nil, err }
			mu.Lock()
			currentSess = next
			s = next
			mu.Unlock()
		}
		if udp {
			return s.DialUDPTunnel(dialCtx, target)
		}
		return s.DialTunnel(dialCtx, target)
	}

	if cfg.DNSPort > 0 {
		alog("HiVoidFFI", fmt.Sprintf("runCore: starting DNS proxy on :%d", cfg.DNSPort))
		dnsProxy := client.NewDNSProxy(client.DNSProxyConfig{
			ListenAddr:    fmt.Sprintf("127.0.0.1:%d", cfg.DNSPort),
			UpstreamDNS:   cfg.DNSUpstream,
			Logger:        logger,
			BypassDomains: bypassDomains,
			BypassIPs:     parsedBypassIPs,
			DirectDNS:     cfg.DirectDNSServers,
		}, func(ctx context.Context, target string) (net.Conn, error) {
			return dialTunnel(ctx, target, false)
		})
		go func() {
			if err := dnsProxy.ListenAndServe(ctx); err != nil {
				alog("HiVoidFFI", "DNS proxy stopped: "+err.Error())
			}
		}()
	}

	if cfg.SocksPort > 0 {
		alog("HiVoidFFI", fmt.Sprintf("runCore: starting SOCKS5 proxy on :%d", cfg.SocksPort))
		proxy := client.NewProxyServer(client.ProxyConfig{
			ListenAddr:    fmt.Sprintf("127.0.0.1:%d", cfg.SocksPort),
			EnableSOCKS5:  true,
			EnableHTTP:    true,
			Logger:        logger,
			BypassDomains: bypassDomains,
			BypassIPs:     parsedBypassIPs,
		}, dialTunnel)
		go func() {
			if err := proxy.ListenAndServe(ctx); err != nil {
				alog("HiVoidFFI", "SOCKS5 proxy stopped: "+err.Error())
			}
		}()
	}

	<-ctx.Done()
	alog("HiVoidFFI", "runCore: context done, stopping")
}

func connectRetry(ctx context.Context, c *transport.Client, log *zap.Logger) (*session.Session, error) {
	var last error
	for i := 1; i <= 5; i++ {
		s, err := c.Connect(ctx)
		if err == nil { return s, nil }
		last = err
		if i < 5 {
			wait := time.Duration(i) * time.Second
			log.Warn("retrying", zap.Int("attempt", i), zap.Duration("wait", wait), zap.Error(err))
			select {
			case <-ctx.Done(): return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
	}
	return nil, fmt.Errorf("connect failed after retries: %w", last)
}

func main() {}