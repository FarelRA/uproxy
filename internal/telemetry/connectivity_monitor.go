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

// NewConnectivityMonitor creates a new connectivity monitor
func NewConnectivityMonitor(onFailure func()) *ConnectivityMonitor {
	m := &ConnectivityMonitor{
		checkInterval:     250 * time.Millisecond,
		idleTimeout:       30 * time.Second,
		asymmetricTimeout: 500 * time.Millisecond,
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

	// Get last activity times
	lastRx, okRx := m.lastRxTime.Load().(time.Time)
	lastTx, okTx := m.lastTxTime.Load().(time.Time)

	if !okRx || !okTx {
		return
	}

	timeSinceRx := now.Sub(lastRx)
	timeSinceTx := now.Sub(lastTx)

	// Scenario 1: Complete idle (no TX or RX) - this is normal, no action needed
	if timeSinceRx > m.idleTimeout && timeSinceTx > m.idleTimeout {
		return
	}

	// Scenario 2: Asymmetric traffic - we're sending but not receiving
	// This indicates: ISP down, firewall blocking, NAT timeout, mobile network issue
	if timeSinceTx < m.asymmetricTimeout && timeSinceRx > m.asymmetricTimeout {
		slog.Warn("Connectivity issue detected: sending packets but not receiving",
			"time_since_rx", timeSinceRx.Round(time.Second),
			"time_since_tx", timeSinceTx.Round(time.Second))
		if m.onFailure != nil {
			m.onFailure()
		}
		return
	}

	// Scenario 3: Long idle on RX but recent TX - potential connection stale
	if timeSinceTx < m.checkInterval && timeSinceRx > m.idleTimeout {
		slog.Warn("Connectivity issue detected: recent TX but no RX for extended period",
			"time_since_rx", timeSinceRx.Round(time.Second))
		if m.onFailure != nil {
			m.onFailure()
		}
		return
	}
}

// Close stops the connectivity monitor
func (m *ConnectivityMonitor) Close() {
	close(m.stopChan)
}
