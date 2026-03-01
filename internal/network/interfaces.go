package network

import "context"

// DiagnosticsProvider defines the interface for network diagnostics.
// This allows for mocking diagnostic behavior in tests.
type DiagnosticsProvider interface {
	DiagnoseFailure(ctx context.Context) DiagnosticResult
}

// Ensure Diagnostics implements DiagnosticsProvider
var _ DiagnosticsProvider = (*Diagnostics)(nil)
