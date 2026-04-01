//go:build windows

package main

import (
	"context"

	"github.com/hivoid-org/hivoid-core/session"
	"go.uber.org/zap"
)

// setupShockSignal is a no-op on Windows currently.
func setupShockSignal(ctx context.Context, m *session.Manager, logger *zap.Logger) {
	// Not supported on Windows signals.
}
