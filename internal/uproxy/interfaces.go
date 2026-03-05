package uproxy

import (
	"context"
	"net"

	"uproxy/internal/network"
)

// PacketConn defines the interface for packet-based network connections.
// This allows for easier testing and mocking of UDP connections.
type PacketConn interface {
	net.PacketConn
}

// DiagnosticsProvider defines the interface for network diagnostics.
// This allows for mocking diagnostic behavior in tests.
type DiagnosticsProvider interface {
	DiagnoseFailure(ctx context.Context) network.DiagnosticResult
}
