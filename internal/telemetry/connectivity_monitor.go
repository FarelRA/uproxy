package telemetry

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// ConnectivityMonitor tracks packet activity and detects connectivity issues
type ConnectivityMonitor struct {
	checkInterval     time.Duration
	idleTimeout       time.Duration
	asymmetricTimeout time.Duration
	onFailure         func() // Callback when connectivity failure is detected
	stopChan          chan struct{}
	lastRxTime        atomic.Value // time.Time
	lastTxTime        atomic.Value // time.Time
}

// NewConnectivityMonitor creates a new connectivity monitor with default timeouts
func NewConnectivityMonitor(onFailure func()) *ConnectivityMonitor {
	return NewConnectivityMonitorWithTimeouts(onFailure, 250*time.Millisecond, 30*time.Second, 10*time.Second)
}

// NewConnectivityMonitorWithTimeouts creates a new connectivity monitor with custom timeouts
func NewConnectivityMonitorWithTimeouts(onFailure func(), checkInterval, idleTimeout, asymmetricTimeout time.Duration) *ConnectivityMonitor {
	m := &ConnectivityMonitor{
		checkInterval:     checkInterval,
		idleTimeout:       idleTimeout,
		asymmetricTimeout: asymmetricTimeout,
		onFailure:         onFailure,
		stopChan:          make(chan struct{}),
	}

	// Initialize activity times
	now := time.Now()
	m.lastRxTime.Store(now)
	m.lastTxTime.Store(now)

	go m.monitorLoop()
	return m
}

// RecordTx records a packet transmission
func (m *ConnectivityMonitor) RecordTx() {
	m.lastTxTime.Store(time.Now())
}

// RecordRx records a packet reception
func (m *ConnectivityMonitor) RecordRx() {
	m.lastRxTime.Store(time.Now())
}

// monitorLoop monitors packet activity and detects connectivity issues
func (m *ConnectivityMonitor) monitorLoop() {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.checkConnectivity()
		}
	}
}

func (m *ConnectivityMonitor) checkConnectivity() {
	now := time.Now()

	// Get last activity times (type assertion always succeeds since atomic.Value enforces type consistency)
	lastRx := m.lastRxTime.Load().(time.Time)
	lastTx := m.lastTxTime.Load().(time.Time)

	timeSinceRx := now.Sub(lastRx)
	timeSinceTx := now.Sub(lastTx)

	slog.Debug("Checking connectivity",
		"time_since_rx", timeSinceRx.Round(time.Millisecond),
		"time_since_tx", timeSinceTx.Round(time.Millisecond))

	// Check for connectivity issues
	if m.isCompletelyIdle(timeSinceRx, timeSinceTx) {
		slog.Debug("Connection idle (normal state)",
			"idle_timeout", m.idleTimeout)
		return // Normal idle state
	}

	if m.hasAsymmetricTraffic(timeSinceRx, timeSinceTx) {
		slog.Warn("Connectivity issue detected: sending packets but not receiving",
			"time_since_rx", timeSinceRx.Round(time.Second),
			"time_since_tx", timeSinceTx.Round(time.Second))
		if m.onFailure != nil {
			m.onFailure()
		}
		return
	}

	if m.hasStaleConnection(timeSinceRx, timeSinceTx) {
		slog.Warn("Connectivity issue detected: recent TX but no RX for extended period",
			"time_since_rx", timeSinceRx.Round(time.Second))
		if m.onFailure != nil {
			m.onFailure()
		}
		return
	}
}

// isCompletelyIdle checks if both TX and RX are idle (normal state)
func (m *ConnectivityMonitor) isCompletelyIdle(timeSinceRx, timeSinceTx time.Duration) bool {
	return timeSinceRx > m.idleTimeout && timeSinceTx > m.idleTimeout
}

// hasAsymmetricTraffic detects when we're sending but not receiving
// This indicates: ISP down, firewall blocking, NAT timeout, mobile network issue
func (m *ConnectivityMonitor) hasAsymmetricTraffic(timeSinceRx, timeSinceTx time.Duration) bool {
	return timeSinceTx < m.asymmetricTimeout && timeSinceRx > m.asymmetricTimeout
}

// hasStaleConnection detects long RX idle with recent TX (potential stale connection)
func (m *ConnectivityMonitor) hasStaleConnection(timeSinceRx, timeSinceTx time.Duration) bool {
	return timeSinceTx < m.checkInterval && timeSinceRx > m.idleTimeout
}

// Close stops the connectivity monitor
func (m *ConnectivityMonitor) Close() {
	close(m.stopChan)
}
