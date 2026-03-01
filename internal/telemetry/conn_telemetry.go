package telemetry

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// ConnTelemetry tracks connection-level metrics (bytes, packets, drops, rebinds)
type ConnTelemetry struct {
	layer     string
	interval  time.Duration
	stopChan  chan struct{}
	txBytes   int64
	rxBytes   int64
	txPackets int64
	rxPackets int64
	drops     int64
	rebinds   int64
}

// NewConnTelemetry creates a new telemetry tracker
func NewConnTelemetry(layer string, interval time.Duration) *ConnTelemetry {
	if interval == 0 {
		interval = 30 * time.Second
	}
	t := &ConnTelemetry{
		layer:    layer,
		interval: interval,
		stopChan: make(chan struct{}),
	}
	go t.logLoop()
	return t
}

// RecordTx records transmitted bytes and packets
func (t *ConnTelemetry) RecordTx(bytes int) {
	atomic.AddInt64(&t.txBytes, int64(bytes))
	atomic.AddInt64(&t.txPackets, 1)
}

// RecordRx records received bytes and packets
func (t *ConnTelemetry) RecordRx(bytes int) {
	atomic.AddInt64(&t.rxBytes, int64(bytes))
	atomic.AddInt64(&t.rxPackets, 1)
}

// RecordDrop records a connection drop/failure
func (t *ConnTelemetry) RecordDrop() {
	atomic.AddInt64(&t.drops, 1)
}

// RecordRebind records a socket rebind event
func (t *ConnTelemetry) RecordRebind() {
	atomic.AddInt64(&t.rebinds, 1)
}

// GetStats returns current telemetry statistics
func (t *ConnTelemetry) GetStats() (txBytes, rxBytes, txPackets, rxPackets, drops, rebinds int64) {
	return atomic.LoadInt64(&t.txBytes),
		atomic.LoadInt64(&t.rxBytes),
		atomic.LoadInt64(&t.txPackets),
		atomic.LoadInt64(&t.rxPackets),
		atomic.LoadInt64(&t.drops),
		atomic.LoadInt64(&t.rebinds)
}

// logLoop periodically logs telemetry data
func (t *ConnTelemetry) logLoop() {
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	var lastTx, lastRx int64

	for {
		select {
		case <-t.stopChan:
			return
		case <-ticker.C:
			tx, rx, txP, rxP, drops, rebinds := t.GetStats()

			// Only log if traffic occurred in the last interval
			if tx != lastTx || rx != lastRx || drops > 0 || rebinds > 0 {
				slog.Info("Transport Telemetry",
					"layer", t.layer,
					"interval", t.interval,
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
}

// Close stops the telemetry logging loop
func (t *ConnTelemetry) Close() {
	close(t.stopChan)
}
