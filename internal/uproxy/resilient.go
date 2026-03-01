package uproxy

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ResilientPacketConn is a custom UDP wrapper that silently swallows kernel-level errors.
type ResilientPacketConn struct {
	mu           sync.RWMutex
	conn         *net.UDPConn
	bindAddr     string
	iface        string
	closed       bool
	reconnecting bool
	reconnectInt time.Duration
	sockBuf      int

	// Telemetry
	txBytes   int64
	rxBytes   int64
	txPackets int64
	rxPackets int64
	drops     int64
	rebinds   int64
}

func NewResilientPacketConn(bindAddr, iface string, reconnectInterval time.Duration, sockBuf int) *ResilientPacketConn {
	if reconnectInterval == 0 {
		reconnectInterval = 1 * time.Second
	}
	r := &ResilientPacketConn{
		bindAddr:     bindAddr,
		iface:        iface,
		reconnectInt: reconnectInterval,
		sockBuf:      sockBuf,
	}
	r.reconnectSync()

	// Spin up telemetry logger
	go r.telemetryLoop()

	return r
}

func (r *ResilientPacketConn) telemetryLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var lastTx, lastRx int64

	for range ticker.C {
		r.mu.RLock()
		closed := r.closed
		r.mu.RUnlock()
		if closed {
			return
		}

		tx := atomic.LoadInt64(&r.txBytes)
		rx := atomic.LoadInt64(&r.rxBytes)
		txP := atomic.LoadInt64(&r.txPackets)
		rxP := atomic.LoadInt64(&r.rxPackets)
		drops := atomic.LoadInt64(&r.drops)
		rebinds := atomic.LoadInt64(&r.rebinds)

		// Only log if traffic occurred in the last 30s
		if tx != lastTx || rx != lastRx || drops > 0 || rebinds > 0 {
			slog.Info("Transport Telemetry (30s interval)",
				"layer", "resilient",
				"tx_bytes", tx,
				"rx_bytes", rx,
				"tx_pkts", txP,
				"rx_pkts", rxP,
				"drops", drops,
				"rebinds", rebinds,
			)
			lastTx = tx
			lastRx = rx
		}
	}
}

func (r *ResilientPacketConn) triggerReconnect() {
	r.mu.Lock()
	if r.reconnecting || r.closed {
		r.mu.Unlock()
		return
	}
	r.reconnecting = true
	r.mu.Unlock()

	atomic.AddInt64(&r.drops, 1)
	slog.Warn("Network interface drop detected. Attempting to rebind socket...", "layer", "resilient")

	go func() {
		defer func() {
			r.mu.Lock()
			r.reconnecting = false
			r.mu.Unlock()
		}()
		r.reconnectSync()
	}()
}

// ForceRebind forces the socket to rebind (useful when network changes are detected externally)
func (r *ResilientPacketConn) ForceRebind() {
	r.mu.Lock()
	if r.reconnecting || r.closed {
		r.mu.Unlock()
		return
	}
	r.reconnecting = true
	r.mu.Unlock()

	slog.Info("Network change detected, rebinding socket...", "layer", "resilient")

	go func() {
		defer func() {
			r.mu.Lock()
			r.reconnecting = false
			r.mu.Unlock()
		}()
		r.reconnectSync()
	}()
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

					atomic.AddInt64(&r.rebinds, 1)
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

		atomic.AddInt64(&r.rxBytes, int64(n))
		atomic.AddInt64(&r.rxPackets, 1)
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

	atomic.AddInt64(&r.txBytes, int64(n))
	atomic.AddInt64(&r.txPackets, 1)
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
