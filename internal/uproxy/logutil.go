package uproxy

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewZapLogger builds a zap logger.
//
// - json=true uses zap's production JSON logger.
// - json=false uses zap's development (console) logger.
// - level is optional (debug|info|warn|error|dpanic|panic|fatal).
func NewZapLogger(json bool, level string) (*zap.Logger, error) {
	var cfg zap.Config
	if json {
		cfg = zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	}

	if strings.TrimSpace(level) != "" {
		var lvl zapcore.Level
		if err := lvl.UnmarshalText([]byte(strings.ToLower(strings.TrimSpace(level)))); err != nil {
			return nil, fmt.Errorf("invalid log level %q: %w", level, err)
		}
		cfg.Level = zap.NewAtomicLevelAt(lvl)
	}

	return cfg.Build()
}
