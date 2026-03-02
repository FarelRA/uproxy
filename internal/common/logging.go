package common

import "log/slog"

// Log logs a message at the specified level with a layer tag
func Log(level slog.Level, layer, msg string, args ...any) {
	allArgs := append([]any{"layer", layer}, args...)
	slog.Log(nil, level, msg, allArgs...)
}

// LogInfo logs an info message with a layer tag
func LogInfo(layer, msg string, args ...any) {
	Log(slog.LevelInfo, layer, msg, args...)
}

// LogError logs an error message with a layer tag
func LogError(layer, msg string, args ...any) {
	Log(slog.LevelError, layer, msg, args...)
}

// LogWarn logs a warning message with a layer tag
func LogWarn(layer, msg string, args ...any) {
	Log(slog.LevelWarn, layer, msg, args...)
}

// LogDebug logs a debug message with a layer tag
func LogDebug(layer, msg string, args ...any) {
	Log(slog.LevelDebug, layer, msg, args...)
}
