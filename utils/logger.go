// Package utils — structured logging for HiVoid.
// Wraps go.uber.org/zap for production-grade structured logging.
package utils

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the package-level logger instance.
var Logger *zap.Logger

func init() {
	Logger, _ = NewLogger(false)
}

// NewLogger creates a new zap logger. Set debug=true to enable verbose output.
func NewLogger(debug bool) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	if debug {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	return cfg.Build()
}

// SetGlobalLogger sets the package-level logger.
func SetGlobalLogger(l *zap.Logger) {
	Logger = l
}

// With returns a child logger with the given fields.
func With(fields ...zap.Field) *zap.Logger {
	return Logger.With(fields...)
}
