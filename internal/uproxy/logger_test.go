package uproxy

import (
	"log/slog"
	"testing"
)

func TestInitLogger(t *testing.T) {
	tests := []struct {
		name   string
		level  string
		format string
	}{
		{"debug text", "debug", "text"},
		{"info text", "info", "text"},
		{"warn text", "warn", "text"},
		{"error text", "error", "text"},
		{"default level", "invalid", "text"},
		{"debug json", "debug", "json"},
		{"info json", "info", "json"},
		{"uppercase level", "DEBUG", "text"},
		{"uppercase format", "info", "JSON"},
		{"mixed case", "Info", "Text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			InitLogger(tt.level, tt.format)

			// Verify logger is set (basic check)
			logger := slog.Default()
			if logger == nil {
				t.Error("Expected non-nil logger")
			}
		})
	}
}

func TestInitLoggerLevels(t *testing.T) {
	// Test that different log levels are actually set
	InitLogger("debug", "text")
	if !slog.Default().Enabled(nil, slog.LevelDebug) {
		t.Error("Debug level should be enabled")
	}

	InitLogger("error", "text")
	if slog.Default().Enabled(nil, slog.LevelDebug) {
		t.Error("Debug level should not be enabled when error level is set")
	}
	if !slog.Default().Enabled(nil, slog.LevelError) {
		t.Error("Error level should be enabled")
	}
}

func TestInitLoggerFormats(t *testing.T) {
	// Test JSON format
	InitLogger("info", "json")
	logger := slog.Default()
	if logger == nil {
		t.Error("Expected non-nil logger for JSON format")
	}

	// Test text format
	InitLogger("info", "text")
	logger = slog.Default()
	if logger == nil {
		t.Error("Expected non-nil logger for text format")
	}

	// Test default format (should be text)
	InitLogger("info", "unknown")
	logger = slog.Default()
	if logger == nil {
		t.Error("Expected non-nil logger for unknown format")
	}
}
