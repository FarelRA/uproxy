package uproxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"uproxy/internal/network"
	"uproxy/internal/telemetry"
)

const (
	// reconnectRetryDelay is the delay between retry attempts after a connection error
	reconnectRetryDelay = 100 * time.Millisecond
)

var errConnectionUnavailable = errors.New("connection unavailable")

const (
	defaultHealthCheckInterval = 250 * time.Millisecond
	defaultFailureThreshold    = 30 * time.Second
	defaultRecoverThreshold    = 500 * time.Millisecond
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

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
}

func NewResilientPacketConn(bindAddr, iface string, reconnectInterval time.Duration, sockBuf int, serverMode bool) *ResilientPacketConn {
	if reconnectInterval == 0 {
		reconnectInterval = 1 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &ResilientPacketConn{
		bindAddr:     bindAddr,
		iface:        iface,
		reconnectInt: reconnectInterval,
		sockBuf:      sockBuf,
		serverMode:   serverMode,
		telemetry:    telemetry.NewConnTelemetry("resilient", 30*time.Second),
		ctx:          ctx,
		cancel:       cancel,
	}

	r.reconnectSync()

	// Only run connectivity monitor for client mode
	// Server doesn't need to rebind when clients die - clients reconnect instead
	if !serverMode {
		r.monitor = telemetry.NewConnectivityMonitorWithTimeouts(
			r.triggerReconnect,
			defaultHealthCheckInterval,
			defaultFailureThreshold,
			defaultRecoverThreshold,
		)
	}

	return r
}

// SetIdleTimeout updates connectivity monitor failure threshold for client mode.
// A non-positive timeout resets to the default threshold.
func (r *ResilientPacketConn) SetIdleTimeout(idleTimeout time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.serverMode {
		return
	}

	if idleTimeout <= 0 {
		idleTimeout = defaultFailureThreshold
	}

	if r.monitor != nil {
		r.monitor.Close()
	}

	r.monitor = telemetry.NewConnectivityMonitorWithTimeouts(
		r.triggerReconnect,
		defaultHealthCheckInterval,
		idleTimeout,
		defaultRecoverThreshold,
	)
}

// SetFailureHandler sets a callback for handling connectivity failures
// The handler receives diagnostic information and can apply specific fixes
func (r *ResilientPacketConn) SetFailureHandler(serverAddr string, handler FailureHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.diagnostics = network.NewDiagnostics(serverAddr, slog.Default())
	r.failureHandler = handler
}

// runDiagnostics performs failure diagnostics and attempts to handle the issue
// Returns true if the failure was handled by a custom handler
func (r *ResilientPacketConn) runDiagnostics(diagnostics *network.Diagnostics, handler FailureHandler) bool {
	if diagnostics == nil {
		slog.Warn("Network interface drop detected. Attempting to rebind socket...", "layer", "resilient")
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	result := diagnostics.DiagnoseFailure(ctx)
	cancel()

	slog.Warn("Connectivity failure detected",
		"layer", "resilient",
		"failure_type", result.FailureType.String(),
		"message", result.Message)

	// Let the failure handler attempt to fix the issue
	if handler != nil {
		return handler(result)
	}
	return false
}

// scheduleReconnect starts a goroutine to perform reconnection
func (r *ResilientPacketConn) scheduleReconnect() {
	go func() {
		defer func() {
			r.mu.Lock()
			r.reconnecting = false
			r.mu.Unlock()
		}()
		r.reconnectSync()
	}()
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

	if r.telemetry != nil {
		r.telemetry.RecordDrop()
	}

	// Diagnose the failure and attempt to handle it
	handled := r.runDiagnostics(diagnostics, handler)

	// If not handled by custom handler, do default rebind
	if !handled {
		r.scheduleReconnect()
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
	// Save old connection reference but DON'T close it yet (make-before-break)
	oldConn := r.conn
	r.mu.Unlock()

	for {
		r.mu.RLock()
		if r.closed {
			r.mu.RUnlock()
			return
		}
		interval := r.reconnectInt
		r.mu.RUnlock()

		// Always bind to all interfaces instead of specific interface
		// Format ":port" means "all interfaces on this port"
		// OS automatically routes through any available interface - no manual rebinding needed!
		udpAddr, err := net.ResolveUDPAddr("udp", r.bindAddr)
		if err == nil {
			conn, err := net.ListenUDP("udp", udpAddr)
			if err == nil {
				OptimizeUDPConn(conn, r.sockBuf)

				// Atomically swap to new connection (no gap!)
				r.mu.Lock()
				r.conn = conn
				r.mu.Unlock()

				// NOW close old connection after new one is active
				if oldConn != nil {
					if err := oldConn.Close(); err != nil {
						slog.Debug("Failed to close old connection after rebind", "error", err)
					}
				}

				if r.telemetry != nil {
					r.telemetry.RecordRebind()
				}
				slog.Info("Successfully bound resilient UDP socket", "layer", "resilient", "addr", udpAddr.String())
				return
			}
		}

		// Context-aware sleep to allow cancellation
		select {
		case <-r.ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (r *ResilientPacketConn) getConn() *net.UDPConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.conn
}

// waitForConnection blocks until a connection is available or the conn is closed
func (r *ResilientPacketConn) waitForConnection() (*net.UDPConn, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		c := r.getConn()
		if c != nil {
			return c, nil
		}
		if r.isClosed() {
			return nil, net.ErrClosed
		}

		select {
		case <-r.ctx.Done():
			return nil, net.ErrClosed
		case <-ticker.C:
		}
	}
}

// shouldRetryError determines if an error should trigger a reconnect and retry
func (r *ResilientPacketConn) shouldRetryError(err error) bool {
	if r.isClosed() {
		return false
	}
	// Don't retry on timeout errors - return them to caller
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return false
	}
	return true
}

func (r *ResilientPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		c, err := r.waitForConnection()
		if err != nil {
			return 0, nil, err
		}

		n, addr, err := c.ReadFrom(p)
		if err != nil {
			if !r.shouldRetryError(err) {
				return 0, nil, err
			}
			r.triggerReconnect()
			time.Sleep(reconnectRetryDelay)
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
	for {
		c, err := r.waitForConnection()
		if err != nil {
			return 0, err
		}

		n, err := c.WriteTo(p, addr)
		if err != nil {
			if !r.shouldRetryError(err) {
				return 0, err
			}
			r.triggerReconnect()
			time.Sleep(reconnectRetryDelay)
			continue
		}

		r.telemetry.RecordTx(n)
		if r.monitor != nil {
			r.monitor.RecordTx()
		}
		return n, nil
	}
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

	// Cancel context to signal all goroutines
	r.cancel()

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
