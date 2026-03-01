package telemetry

import (
	"sync"
	"testing"
	"time"
)

// TestConnTelemetry_RecordTx tests recording transmitted data
func TestConnTelemetry_RecordTx(t *testing.T) {
	tel := NewConnTelemetry("test", 1*time.Hour) // Long interval to avoid logging
	defer tel.Close()

	tel.RecordTx(100)
	tel.RecordTx(200)

	txBytes, _, txPackets, _, _, _ := tel.GetStats()
	if txBytes != 300 {
		t.Errorf("Expected txBytes=300, got %d", txBytes)
	}
	if txPackets != 2 {
		t.Errorf("Expected txPackets=2, got %d", txPackets)
	}
}

// TestConnTelemetry_RecordRx tests recording received data
func TestConnTelemetry_RecordRx(t *testing.T) {
	tel := NewConnTelemetry("test", 1*time.Hour)
	defer tel.Close()

	tel.RecordRx(150)
	tel.RecordRx(250)

	_, rxBytes, _, rxPackets, _, _ := tel.GetStats()
	if rxBytes != 400 {
		t.Errorf("Expected rxBytes=400, got %d", rxBytes)
	}
	if rxPackets != 2 {
		t.Errorf("Expected rxPackets=2, got %d", rxPackets)
	}
}

// TestConnTelemetry_RecordDrop tests recording connection drops
func TestConnTelemetry_RecordDrop(t *testing.T) {
	tel := NewConnTelemetry("test", 1*time.Hour)
	defer tel.Close()

	tel.RecordDrop()
	tel.RecordDrop()
	tel.RecordDrop()

	_, _, _, _, drops, _ := tel.GetStats()
	if drops != 3 {
		t.Errorf("Expected drops=3, got %d", drops)
	}
}

// TestConnTelemetry_RecordRebind tests recording rebind events
func TestConnTelemetry_RecordRebind(t *testing.T) {
	tel := NewConnTelemetry("test", 1*time.Hour)
	defer tel.Close()

	tel.RecordRebind()
	tel.RecordRebind()

	_, _, _, _, _, rebinds := tel.GetStats()
	if rebinds != 2 {
		t.Errorf("Expected rebinds=2, got %d", rebinds)
	}
}

// TestConnTelemetry_Concurrent tests thread safety with concurrent access
func TestConnTelemetry_Concurrent(t *testing.T) {
	tel := NewConnTelemetry("test", 1*time.Hour)
	defer tel.Close()

	var wg sync.WaitGroup
	goroutines := 100
	iterations := 100

	// Concurrent TX recording
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				tel.RecordTx(10)
			}
		}()
	}

	// Concurrent RX recording
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				tel.RecordRx(20)
			}
		}()
	}

	// Concurrent drop recording
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				tel.RecordDrop()
			}
		}()
	}

	wg.Wait()

	txBytes, rxBytes, txPackets, rxPackets, drops, _ := tel.GetStats()
	expectedTxBytes := int64(goroutines * iterations * 10)
	expectedRxBytes := int64(goroutines * iterations * 20)
	expectedPackets := int64(goroutines * iterations)

	if txBytes != expectedTxBytes {
		t.Errorf("Expected txBytes=%d, got %d", expectedTxBytes, txBytes)
	}
	if rxBytes != expectedRxBytes {
		t.Errorf("Expected rxBytes=%d, got %d", expectedRxBytes, rxBytes)
	}
	if txPackets != expectedPackets {
		t.Errorf("Expected txPackets=%d, got %d", expectedPackets, txPackets)
	}
	if rxPackets != expectedPackets {
		t.Errorf("Expected rxPackets=%d, got %d", expectedPackets, rxPackets)
	}
	if drops != expectedPackets {
		t.Errorf("Expected drops=%d, got %d", expectedPackets, drops)
	}
}

// TestConnTelemetry_DefaultInterval tests default interval is set
func TestConnTelemetry_DefaultInterval(t *testing.T) {
	tel := NewConnTelemetry("test", 0) // Zero interval should use default
	defer tel.Close()

	if tel.interval != 30*time.Second {
		t.Errorf("Expected default interval=30s, got %v", tel.interval)
	}
}

// TestConnectivityMonitor_RecordActivity tests recording TX/RX activity
func TestConnectivityMonitor_RecordActivity(t *testing.T) {
	called := false
	onFailure := func() {
		called = true
	}

	mon := NewConnectivityMonitor(onFailure)
	defer mon.Close()

	// Record activity
	mon.RecordTx()
	time.Sleep(10 * time.Millisecond)
	mon.RecordRx()

	// Verify times are stored
	lastTx, okTx := mon.lastTxTime.Load().(time.Time)
	lastRx, okRx := mon.lastRxTime.Load().(time.Time)

	if !okTx || !okRx {
		t.Fatal("Failed to load activity times")
	}

	if lastTx.IsZero() || lastRx.IsZero() {
		t.Error("Activity times should not be zero")
	}

	// Should not trigger failure with recent activity
	time.Sleep(300 * time.Millisecond)
	if called {
		t.Error("onFailure should not be called with recent activity")
	}
}

// TestConnectivityMonitor_AsymmetricTraffic tests detection of asymmetric traffic
func TestConnectivityMonitor_AsymmetricTraffic(t *testing.T) {
	called := false
	onFailure := func() {
		called = true
	}

	mon := NewConnectivityMonitor(onFailure)
	defer mon.Close()

	// Simulate sending but not receiving
	now := time.Now()
	mon.lastTxTime.Store(now)                       // Recent TX
	mon.lastRxTime.Store(now.Add(-1 * time.Second)) // Old RX (1 second ago)

	// Wait for monitor to detect the issue
	time.Sleep(300 * time.Millisecond)

	if !called {
		t.Error("onFailure should be called for asymmetric traffic")
	}
}

// TestConnectivityMonitor_IdleTimeout tests idle timeout scenario
func TestConnectivityMonitor_IdleTimeout(t *testing.T) {
	called := false
	onFailure := func() {
		called = true
	}

	mon := NewConnectivityMonitor(onFailure)
	defer mon.Close()

	// Simulate both TX and RX being idle for a long time
	now := time.Now()
	mon.lastTxTime.Store(now.Add(-35 * time.Second))
	mon.lastRxTime.Store(now.Add(-35 * time.Second))

	// Wait for monitor check
	time.Sleep(300 * time.Millisecond)

	// Should NOT trigger failure for complete idle (this is normal)
	if called {
		t.Error("onFailure should not be called for complete idle")
	}
}

// TestConnectivityMonitor_RecentTxNoRx tests recent TX but no RX scenario
func TestConnectivityMonitor_RecentTxNoRx(t *testing.T) {
	called := false
	onFailure := func() {
		called = true
	}

	mon := NewConnectivityMonitor(onFailure)
	defer mon.Close()

	// Simulate very recent TX but no RX for extended period
	now := time.Now()
	mon.lastTxTime.Store(now)                        // Very recent TX
	mon.lastRxTime.Store(now.Add(-35 * time.Second)) // Old RX (35 seconds ago)

	// Wait for monitor to detect
	time.Sleep(300 * time.Millisecond)

	if !called {
		t.Error("onFailure should be called for recent TX but no RX")
	}
}

// TestConnectivityMonitor_NilCallback tests that nil callback doesn't panic
func TestConnectivityMonitor_NilCallback(t *testing.T) {
	mon := NewConnectivityMonitor(nil)
	defer mon.Close()

	// Trigger failure condition with nil callback
	now := time.Now()
	mon.lastTxTime.Store(now)
	mon.lastRxTime.Store(now.Add(-1 * time.Second))

	// Wait for monitor check - should not panic
	time.Sleep(300 * time.Millisecond)
}

// TestConnectivityMonitor_Close tests that Close stops the monitor
func TestConnectivityMonitor_Close(t *testing.T) {
	callCount := 0
	onFailure := func() {
		callCount++
	}

	mon := NewConnectivityMonitor(onFailure)

	// Trigger failure condition
	now := time.Now()
	mon.lastTxTime.Store(now)
	mon.lastRxTime.Store(now.Add(-1 * time.Second))

	// Wait for first detection
	time.Sleep(300 * time.Millisecond)
	firstCount := callCount

	// Close the monitor
	mon.Close()

	// Wait and verify no more calls
	time.Sleep(300 * time.Millisecond)
	if callCount != firstCount {
		t.Error("onFailure should not be called after Close")
	}
}
