//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hivoid-org/hivoid-core/session"
	"go.uber.org/zap"
)

func setupShockSignal(ctx context.Context, m *session.Manager, logger *zap.Logger) {
	shockChan := make(chan os.Signal, 1)
	signal.Notify(shockChan, syscall.SIGUSR1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-shockChan:
				logger.Info("shock signal (SIGUSR1) received, force-kicking sessions")
				m.KickAll()
			}
		}
	}()
}
