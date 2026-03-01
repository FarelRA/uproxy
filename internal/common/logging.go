package common

import "log/slog"

// LogInfo logs an info message with a layer tag
func LogInfo(layer, msg string, args ...any) {
	allArgs := append([]any{"layer", layer}, args...)
	slog.Info(msg, allArgs...)
}

// LogError logs an error message with a layer tag
func LogError(layer, msg string, args ...any) {
	allArgs := append([]any{"layer", layer}, args...)
	slog.Error(msg, allArgs...)
}

// LogWarn logs a warning message with a layer tag
func LogWarn(layer, msg string, args ...any) {
	allArgs := append([]any{"layer", layer}, args...)
	slog.Warn(msg, allArgs...)
}

// LogDebug logs a debug message with a layer tag
func LogDebug(layer, msg string, args ...any) {
	allArgs := append([]any{"layer", layer}, args...)
	slog.Debug(msg, allArgs...)
}
