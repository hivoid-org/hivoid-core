package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hivoid-org/hivoid-core/session"
	"go.uber.org/zap"
)

type userState struct {
	uuid       [16]byte
	email      atomic.Value // string
	enabled    atomic.Bool
	expireAt   atomic.Int64 // unix seconds, 0 = never
	bytesIn    atomic.Uint64
	bytesOut   atomic.Uint64
	dataLimit  atomic.Int64 // volume limit, 0 = unlimited
	bandwidth  *tokenBucket
}

// UserControlManager tracks per-user traffic, expiry, and bandwidth state.
type UserControlManager struct {
	logger      *zap.Logger
	persistPath string
	users       sync.Map // map[[16]byte]*userState
}

func NewUserControlManager(logger *zap.Logger, persistPath string) *UserControlManager {
	m := &UserControlManager{
		logger:      logger,
		persistPath: persistPath,
	}
	m.loadPersisted()
	return m
}

func (m *UserControlManager) getOrCreate(uuid [16]byte) *userState {
	if v, ok := m.users.Load(uuid); ok {
		return v.(*userState)
	}
	st := &userState{uuid: uuid, bandwidth: newTokenBucket(0)}
	actual, _ := m.users.LoadOrStore(uuid, st)
	return actual.(*userState)
}

// ApplyPolicies atomically updates runtime policies while preserving counters.
func (m *UserControlManager) ApplyPolicies(policies map[[16]byte]session.UserPolicy) {
	for uuid, p := range policies {
		st := m.getOrCreate(uuid)
		st.email.Store(p.Email)
		st.enabled.Store(p.Enabled)
		st.expireAt.Store(p.ExpireAtUnix)
		st.dataLimit.Store(p.DataLimit)
		st.bandwidth.SetKBytesPerSec(p.BandwidthLimit)
		if st.bytesIn.Load() == 0 && p.BytesIn > 0 {
			st.bytesIn.Store(p.BytesIn)
		}
		if st.bytesOut.Load() == 0 && p.BytesOut > 0 {
			st.bytesOut.Store(p.BytesOut)
		}
	}
}

func (m *UserControlManager) AllowNewConnection(uuid [16]byte) error {
	v, ok := m.users.Load(uuid)
	if !ok {
		return nil
	}
	st := v.(*userState)
	if !st.enabled.Load() {
		return fmt.Errorf("user disabled")
	}
	exp := st.expireAt.Load()
	if exp > 0 && time.Now().Unix() > exp {
		return fmt.Errorf("user expired")
	}
	limit := st.dataLimit.Load()
	if limit > 0 && st.bytesIn.Load()+st.bytesOut.Load() >= uint64(limit) {
		return fmt.Errorf("data limit reached")
	}
	return nil
}

func (m *UserControlManager) IsExpired(uuid [16]byte) bool {
	v, ok := m.users.Load(uuid)
	if !ok {
		return false
	}
	exp := v.(*userState).expireAt.Load()
	return exp > 0 && time.Now().Unix() > exp
}

func (m *UserControlManager) Throttle(uuid [16]byte, n int) {
	if n <= 0 {
		return
	}
	v, ok := m.users.Load(uuid)
	if !ok {
		return
	}
	v.(*userState).bandwidth.WaitN(int64(n))
}

func (m *UserControlManager) AddBytesIn(uuid [16]byte, n uint64) {
	if n == 0 {
		return
	}
	st := m.getOrCreate(uuid)
	st.bytesIn.Add(n)
}

func (m *UserControlManager) AddBytesOut(uuid [16]byte, n uint64) {
	if n == 0 {
		return
	}
	st := m.getOrCreate(uuid)
	st.bytesOut.Add(n)
}

func (m *UserControlManager) UserUsage(uuid [16]byte) (bytesIn, bytesOut uint64) {
	v, ok := m.users.Load(uuid)
	if !ok {
		return 0, 0
	}
	st := v.(*userState)
	return st.bytesIn.Load(), st.bytesOut.Load()
}

func (m *UserControlManager) StartPeriodicFlush(stop <-chan struct{}, every time.Duration) {
	if every <= 0 {
		every = 10 * time.Second
	}
	ticker := time.NewTicker(every)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := m.Flush(); err != nil {
					m.logger.Warn("usage flush failed", zap.Error(err))
				}
			}
		}
	}()
}

type persistedUsage struct {
	Users []persistedUser `json:"users"`
}

type persistedUser struct {
	UUID     string `json:"uuid"`
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

func (m *UserControlManager) loadPersisted() {
	if m.persistPath == "" {
		return
	}
	data, err := os.ReadFile(m.persistPath)
	if err != nil {
		return
	}
	var snap persistedUsage
	if err := json.Unmarshal(data, &snap); err != nil {
		return
	}
	for _, u := range snap.Users {
		id, err := parseUUID(u.UUID)
		if err != nil {
			continue
		}
		st := m.getOrCreate(id)
		if st.bytesIn.Load() < u.BytesIn {
			st.bytesIn.Store(u.BytesIn)
		}
		if st.bytesOut.Load() < u.BytesOut {
			st.bytesOut.Store(u.BytesOut)
		}
	}
}

func (m *UserControlManager) Flush() error {
	if m.persistPath == "" {
		return nil
	}
	snap := persistedUsage{Users: make([]persistedUser, 0, 256)}
	m.users.Range(func(key, value any) bool {
		uuid := key.([16]byte)
		st := value.(*userState)
		snap.Users = append(snap.Users, persistedUser{
			UUID:     formatUUID(uuid),
			BytesIn:  st.bytesIn.Load(),
			BytesOut: st.bytesOut.Load(),
		})
		return true
	})
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.persistPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp := m.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, m.persistPath)
}

func parseUUID(raw string) ([16]byte, error) {
	var out [16]byte
	tmp := raw
	for _, idx := range []int{8, 13, 18, 23} {
		if len(tmp) <= idx || tmp[idx] != '-' {
			return out, fmt.Errorf("invalid uuid")
		}
	}
	hex := make([]byte, 0, 32)
	for i := 0; i < len(tmp); i++ {
		if tmp[i] != '-' {
			hex = append(hex, tmp[i])
		}
	}
	if len(hex) != 32 {
		return out, fmt.Errorf("invalid uuid")
	}
	for i := 0; i < 16; i++ {
		hi, ok := hexNibble(hex[i*2])
		if !ok {
			return out, fmt.Errorf("invalid uuid")
		}
		lo, ok := hexNibble(hex[i*2+1])
		if !ok {
			return out, fmt.Errorf("invalid uuid")
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func formatUUID(id [16]byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 36)
	j := 0
	for i := 0; i < 16; i++ {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[j] = '-'
			j++
		}
		out[j] = hex[id[i]>>4]
		out[j+1] = hex[id[i]&0x0f]
		j += 2
	}
	return string(out)
}

type tokenBucket struct {
	rateBytes atomic.Int64 // bytes per second, 0 = unlimited
	burst     atomic.Int64
	tokens    atomic.Int64
	lastRefill atomic.Int64 // unix nanos
}

func newTokenBucket(kbytesPerSec int64) *tokenBucket {
	b := &tokenBucket{}
	b.SetKBytesPerSec(kbytesPerSec)
	return b
}

func (b *tokenBucket) SetKBytesPerSec(kbytesPerSec int64) {
	rate := kbytesPerSec * 1024
	if rate < 0 {
		rate = 0
	}
	now := time.Now().UnixNano()
	b.rateBytes.Store(rate)
	if rate == 0 {
		b.burst.Store(0)
		b.tokens.Store(0)
		b.lastRefill.Store(now)
		return
	}
	burst := rate * 2
	minBurst := int64(64 * 1024)
	if burst < minBurst {
		burst = minBurst
	}
	b.burst.Store(burst)
	if b.tokens.Load() > burst || b.tokens.Load() == 0 {
		b.tokens.Store(burst)
	}
	b.lastRefill.Store(now)
}

func (b *tokenBucket) refill(now int64) {
	last := b.lastRefill.Load()
	if now <= last {
		return
	}
	if !b.lastRefill.CompareAndSwap(last, now) {
		return
	}
	rate := b.rateBytes.Load()
	if rate <= 0 {
		return
	}
	elapsed := now - last
	add := (elapsed * rate) / int64(time.Second)
	if add <= 0 {
		return
	}
	for {
		old := b.tokens.Load()
		next := old + add
		burst := b.burst.Load()
		if next > burst {
			next = burst
		}
		if b.tokens.CompareAndSwap(old, next) {
			return
		}
	}
}

func (b *tokenBucket) WaitN(n int64) {
	if n <= 0 {
		return
	}
	for {
		rate := b.rateBytes.Load()
		if rate <= 0 {
			return
		}
		now := time.Now().UnixNano()
		b.refill(now)
		available := b.tokens.Load()
		if available >= n {
			if b.tokens.CompareAndSwap(available, available-n) {
				return
			}
			continue
		}
		deficit := n - available
		waitNs := (deficit * int64(time.Second)) / rate
		if waitNs < int64(time.Millisecond) {
			waitNs = int64(time.Millisecond)
		}
		time.Sleep(time.Duration(waitNs))
	}
}
