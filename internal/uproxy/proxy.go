package uproxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"time"

	"golang.org/x/sync/errgroup"
)

// DefaultTCPBufSize is the default buffer size for proxy operations.
const DefaultTCPBufSize = 32768

// ProxyBidi establishes a highly-optimized, zero-copy bidirectional data pipe
// between two connections (e.g., an SSH channel and a raw TCP/UDP socket).
// It blocks until both sides of the connection are completely closed, and records rich telemetry.
// The bufSize parameter controls the buffer size for copying data.
func ProxyBidi(ctx context.Context, a, b io.ReadWriteCloser, role, target string, bufSize int) error {
	defer a.Close()
	defer b.Close()

	start := time.Now()
	slog.Info("Stream started", "layer", "proxy", "role", role, "target", target)

	var txBytes, rxBytes int64

	g, _ := errgroup.WithContext(ctx)

	// Stream: A -> B
	g.Go(func() error {
		buf := make([]byte, bufSize)
		n, err := io.CopyBuffer(a, b, buf)
		txBytes = n

		_ = a.Close()
		return err
	})

	// Stream: B -> A
	g.Go(func() error {
		buf := make([]byte, bufSize)
		n, err := io.CopyBuffer(b, a, buf)
		rxBytes = n

		_ = b.Close()
		return err
	})

	err := g.Wait()
	duration := time.Since(start)

	slog.Info("Stream closed",
		"layer", "proxy",
		"role", role,
		"target", target,
		"tx_bytes", txBytes,
		"rx_bytes", rxBytes,
		"duration", duration.String(),
		"error", err,
	)

	return err
}

// OptimizeTCPConn rigorously disables Nagle's Algorithm (SetNoDelay=true).
func OptimizeTCPConn(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetNoDelay(true); err != nil {
			slog.Debug("Failed to set TCP_NODELAY on proxy target", "error", err)
		}
	}
}
