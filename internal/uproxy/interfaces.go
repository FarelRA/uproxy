package uproxy

import (
	"context"
	"net"
	"time"

	"uproxy/internal/network"
)

// PacketConn defines the interface for packet-based network connections.
// This allows for easier testing and mocking of UDP connections.
type PacketConn interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
	Close() error
	LocalAddr() net.Addr
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// DiagnosticsProvider defines the interface for network diagnostics.
// This allows for mocking diagnostic behavior in tests.
type DiagnosticsProvider interface {
	DiagnoseFailure(ctx context.Context) network.DiagnosticResult
}

// Ensure ResilientPacketConn implements PacketConn
var _ PacketConn = (*ResilientPacketConn)(nil)
