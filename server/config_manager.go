package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"time"

	"github.com/hivoid-org/hivoid-core/config"
	"go.uber.org/zap"
)

// ConfigManager watches a config file and atomically applies validated updates.
type ConfigManager struct {
	path      string
	interval  time.Duration
	logger    *zap.Logger
	lastSeen  [32]byte
	initialized bool
}

func NewConfigManager(path string, interval time.Duration, logger *zap.Logger) *ConfigManager {
	if interval <= 0 {
		interval = time.Second
	}
	return &ConfigManager{
		path:     path,
		interval: interval,
		logger:   logger,
	}
}

// Start blocks until ctx is canceled.
// It validates each changed config before invoking apply.
func (m *ConfigManager) Start(ctx context.Context, apply func(*config.ServerConfig) error) error {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	if err := m.reloadOnce(apply); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := m.reloadOnce(apply); err != nil {
				m.logger.Warn("config reload rejected", zap.Error(err))
			}
		}
	}
}

func (m *ConfigManager) reloadOnce(apply func(*config.ServerConfig) error) error {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	sum := sha256.Sum256(data)
	if m.initialized && sum == m.lastSeen {
		return nil
	}
	m.lastSeen = sum
	m.initialized = true

	cfg, err := config.LoadServerJSON(m.path)
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := apply(cfg); err != nil {
		return fmt.Errorf("apply config: %w", err)
	}
	m.logger.Info("config reload applied", zap.String("path", m.path))
	return nil
}
