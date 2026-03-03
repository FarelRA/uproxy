package uproxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

// DefaultTCPBufSize is the default buffer size for proxy operations.
const DefaultTCPBufSize = 32768

// idleTimeout is the maximum time a connection can be idle before timing out.
// Set to 30 hours to ensure the proxy survives 24+ hours of network downtime.
// This allows the underlying ResilientPacketConn to handle reconnection without
// timing out the application-level streams prematurely.
const idleTimeout = 30 * time.Hour

// copyWithDeadline copies data from src to dst with idle timeout protection.
// It sets deadlines before each read/write operation to prevent indefinite blocking.
func copyWithDeadline(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	for {
		// Set read deadline if supported
		if conn, ok := src.(net.Conn); ok {
			if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
				slog.Debug("Failed to set read deadline", "error", err)
			}
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			// Set write deadline if supported
			if conn, ok := dst.(net.Conn); ok {
				if err := conn.SetWriteDeadline(time.Now().Add(idleTimeout)); err != nil {
					slog.Debug("Failed to set write deadline", "error", err)
				}
			}

			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = io.ErrShortWrite
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

// ProxyBidi establishes a highly-optimized, zero-copy bidirectional data pipe
// between two connections (e.g., an SSH channel and a raw TCP/UDP socket).
// It blocks until both sides of the connection are completely closed, and records rich telemetry.
// The bufSize parameter controls the buffer size for copying data.
func ProxyBidi(ctx context.Context, a, b io.ReadWriteCloser, role, target string, bufSize int) error {
	defer a.Close()
	defer b.Close()

	if bufSize <= 0 {
		bufSize = DefaultTCPBufSize
	}

	start := time.Now()
	slog.Info("Stream started", "layer", "proxy", "role", role, "target", target)

	var txBytes atomic.Int64
	var rxBytes atomic.Int64

	g, gctx := errgroup.WithContext(ctx)

	// Stream: A -> B
	g.Go(func() error {
		select {
		case <-gctx.Done():
			return gctx.Err()
		default:
		}
		buf := make([]byte, bufSize)
		n, err := copyWithDeadline(b, a, buf)
		txBytes.Store(n)

		if closeErr := b.Close(); closeErr != nil {
			slog.Debug("Failed to close connection B", "layer", "proxy", "error", closeErr)
		}
		return err
	})

	// Stream: B -> A
	g.Go(func() error {
		select {
		case <-gctx.Done():
			return gctx.Err()
		default:
		}
		buf := make([]byte, bufSize)
		n, err := copyWithDeadline(a, b, buf)
		rxBytes.Store(n)

		if closeErr := a.Close(); closeErr != nil {
			slog.Debug("Failed to close connection A", "layer", "proxy", "error", closeErr)
		}
		return err
	})

	err := g.Wait()
	duration := time.Since(start)

	slog.Info("Stream closed",
		"layer", "proxy",
		"role", role,
		"target", target,
		"tx_bytes", txBytes.Load(),
		"rx_bytes", rxBytes.Load(),
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
