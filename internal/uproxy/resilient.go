package uproxy

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"uproxy/internal/network"
	"uproxy/internal/telemetry"
)

// FailureHandler is called when a connectivity failure is detected
// It receives the diagnostic result and should return true if it handled the failure
type FailureHandler func(result network.DiagnosticResult) bool

// ResilientPacketConn is a UDP wrapper that automatically reconnects on errors
type ResilientPacketConn struct {
	mu           sync.RWMutex
	conn         *net.UDPConn
	bindAddr     string
	iface        string
	closed       bool
	reconnecting bool
	reconnectInt time.Duration
	sockBuf      int
	serverMode   bool // If true, disables connectivity monitoring (for server listening sockets)

	// Failure handling
	diagnostics    *network.Diagnostics
	failureHandler FailureHandler

	// Extracted components
	telemetry *telemetry.ConnTelemetry
	monitor   *telemetry.ConnectivityMonitor
}

func NewResilientPacketConn(bindAddr, iface string, reconnectInterval time.Duration, sockBuf int, serverMode bool) *ResilientPacketConn {
	if reconnectInterval == 0 {
		reconnectInterval = 1 * time.Second
	}
	r := &ResilientPacketConn{
		bindAddr:     bindAddr,
		iface:        iface,
		reconnectInt: reconnectInterval,
		sockBuf:      sockBuf,
		serverMode:   serverMode,
		telemetry:    telemetry.NewConnTelemetry("resilient", 30*time.Second),
	}

	r.reconnectSync()

	// Only run connectivity monitor for client mode
	// Server doesn't need to rebind when clients die - clients reconnect instead
	if !serverMode {
		r.monitor = telemetry.NewConnectivityMonitor(r.triggerReconnect)
	}

	return r
}

// SetFailureHandler sets a callback for handling connectivity failures
// The handler receives diagnostic information and can apply specific fixes
func (r *ResilientPacketConn) SetFailureHandler(serverAddr string, handler FailureHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.diagnostics = network.NewDiagnostics(serverAddr, slog.Default())
	r.failureHandler = handler
}

func (r *ResilientPacketConn) triggerReconnect() {
	r.mu.Lock()
	if r.reconnecting || r.closed {
		r.mu.Unlock()
		return
	}
	r.reconnecting = true
	diagnostics := r.diagnostics
	handler := r.failureHandler
	r.mu.Unlock()

	r.telemetry.RecordDrop()

	// Diagnose the failure if diagnostics are available
	var handled bool
	if diagnostics != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result := diagnostics.DiagnoseFailure(ctx)
		cancel()

		slog.Warn("Connectivity failure detected",
			"layer", "resilient",
			"failure_type", result.FailureType.String(),
			"message", result.Message)

		// Let the failure handler attempt to fix the issue
		if handler != nil {
			handled = handler(result)
		}
	} else {
		slog.Warn("Network interface drop detected. Attempting to rebind socket...", "layer", "resilient")
	}

	// If not handled by custom handler, do default rebind
	if !handled {
		go func() {
			defer func() {
				r.mu.Lock()
				r.reconnecting = false
				r.mu.Unlock()
			}()
			r.reconnectSync()
		}()
	} else {
		r.mu.Lock()
		r.reconnecting = false
		r.mu.Unlock()
	}
}

func (r *ResilientPacketConn) reconnectSync() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
	r.mu.Unlock()

	for {
		r.mu.RLock()
		if r.closed {
			r.mu.RUnlock()
			return
		}
		interval := r.reconnectInt
		r.mu.RUnlock()

		addr, err := BindAddrForInterface(r.bindAddr, r.iface)
		if err == nil {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err == nil {
				conn, err := net.ListenUDP("udp", udpAddr)
				if err == nil {
					OptimizeUDPConn(conn, r.sockBuf)
					r.mu.Lock()
					r.conn = conn
					r.mu.Unlock()

					r.telemetry.RecordRebind()
					slog.Info("Successfully bound resilient UDP socket", "layer", "resilient", "addr", udpAddr.String())
					return
				}
			}
		}
		time.Sleep(interval)
	}
}

func (r *ResilientPacketConn) getConn() *net.UDPConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conn
}

func (r *ResilientPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		c := r.getConn()
		if c == nil {
			if r.isClosed() {
				return 0, nil, net.ErrClosed
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n, addr, err := c.ReadFrom(p)
		if err != nil {
			if r.isClosed() {
				return 0, nil, net.ErrClosed
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return 0, nil, err
			}
			r.triggerReconnect()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		r.telemetry.RecordRx(n)
		if r.monitor != nil {
			r.monitor.RecordRx()
		}
		return n, addr, nil
	}
}

func (r *ResilientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c := r.getConn()
	if c == nil {
		if r.isClosed() {
			return 0, net.ErrClosed
		}
		return len(p), nil
	}

	n, err = c.WriteTo(p, addr)
	if err != nil {
		if r.isClosed() {
			return 0, net.ErrClosed
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return 0, err
		}
		r.triggerReconnect()
		return len(p), nil
	}

	r.telemetry.RecordTx(n)
	if r.monitor != nil {
		r.monitor.RecordTx()
	}
	return n, nil
}

func (r *ResilientPacketConn) SetReadBuffer(bytes int) error {
	if c := r.getConn(); c != nil {
		return c.SetReadBuffer(bytes)
	}
	return nil
}

func (r *ResilientPacketConn) SetWriteBuffer(bytes int) error {
	if c := r.getConn(); c != nil {
		return c.SetWriteBuffer(bytes)
	}
	return nil
}

func (r *ResilientPacketConn) isClosed() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.closed
}

func (r *ResilientPacketConn) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true

	// Close extracted components
	if r.telemetry != nil {
		r.telemetry.Close()
	}
	if r.monitor != nil {
		r.monitor.Close()
	}

	if r.conn != nil {
		return r.conn.Close()
	}
	return nil
}

func (r *ResilientPacketConn) LocalAddr() net.Addr {
	if c := r.getConn(); c != nil {
		return c.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (r *ResilientPacketConn) SetDeadline(t time.Time) error {
	if c := r.getConn(); c != nil {
		return c.SetDeadline(t)
	}
	return nil
}

func (r *ResilientPacketConn) SetReadDeadline(t time.Time) error {
	if c := r.getConn(); c != nil {
		return c.SetReadDeadline(t)
	}
	return nil
}

func (r *ResilientPacketConn) SetWriteDeadline(t time.Time) error {
	if c := r.getConn(); c != nil {
		return c.SetWriteDeadline(t)
	}
	return nil
}
