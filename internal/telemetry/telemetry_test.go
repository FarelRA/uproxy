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

// TestConnTelemetry_LogLoop_WithActivity tests that logLoop logs when there's activity
func TestConnTelemetry_LogLoop_WithActivity(t *testing.T) {
	tel := NewConnTelemetry("test", 100*time.Millisecond) // Short interval
	defer tel.Close()

	// Record some activity
	tel.RecordTx(100)
	tel.RecordRx(200)
	tel.RecordDrop()
	tel.RecordRebind()

	// Wait for at least one log cycle
	time.Sleep(150 * time.Millisecond)

	// Verify stats are recorded
	txBytes, rxBytes, _, _, drops, rebinds := tel.GetStats()
	if txBytes != 100 {
		t.Errorf("Expected txBytes=100, got %d", txBytes)
	}
	if rxBytes != 200 {
		t.Errorf("Expected rxBytes=200, got %d", rxBytes)
	}
	if drops != 1 {
		t.Errorf("Expected drops=1, got %d", drops)
	}
	if rebinds != 1 {
		t.Errorf("Expected rebinds=1, got %d", rebinds)
	}
}

// TestConnTelemetry_LogLoop_NoActivity tests that logLoop doesn't log when there's no activity
func TestConnTelemetry_LogLoop_NoActivity(t *testing.T) {
	tel := NewConnTelemetry("test", 100*time.Millisecond) // Short interval
	defer tel.Close()

	// Don't record any activity, just wait for log cycles
	time.Sleep(250 * time.Millisecond)

	// Verify no stats (all zeros)
	txBytes, rxBytes, txPackets, rxPackets, drops, rebinds := tel.GetStats()
	if txBytes != 0 || rxBytes != 0 || txPackets != 0 || rxPackets != 0 || drops != 0 || rebinds != 0 {
		t.Error("Expected all stats to be zero with no activity")
	}
}

// TestConnectivityMonitor_CompleteIdle tests the scenario where both TX and RX are idle
func TestConnectivityMonitor_CompleteIdle(t *testing.T) {
	called := false
	onFailure := func() {
		called = true
	}

	// Use short timeouts for testing
	mon := NewConnectivityMonitorWithTimeouts(onFailure, 50*time.Millisecond, 200*time.Millisecond, 100*time.Millisecond)

	// Simulate old activity times (more than idle timeout ago)
	oldTime := time.Now().Add(-300 * time.Millisecond)
	mon.lastRxTime.Store(oldTime)
	mon.lastTxTime.Store(oldTime)

	// Wait for monitor check
	time.Sleep(100 * time.Millisecond)

	mon.Close()

	// Should not trigger failure when completely idle
	if called {
		t.Error("onFailure should not be called when completely idle")
	}
}

// TestConnectivityMonitor_BothIdle tests when both TX and RX are idle beyond timeout
func TestConnectivityMonitor_BothIdle(t *testing.T) {
	called := false
	onFailure := func() {
		called = true
	}

	// Use very short timeouts for testing
	mon := NewConnectivityMonitorWithTimeouts(onFailure, 50*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)

	// Wait for both to become idle
	time.Sleep(200 * time.Millisecond)

	mon.Close()

	// Should not trigger failure when both are idle (no activity at all)
	if called {
		t.Error("onFailure should not be called when both TX and RX are idle")
	}
}

// TestConnectivityMonitor_OnlyRxIdle tests when RX is idle but TX is active
func TestConnectivityMonitor_OnlyRxIdle(t *testing.T) {
	called := false
	onFailure := func() {
		called = true
	}

	// Use very short timeouts for testing
	mon := NewConnectivityMonitorWithTimeouts(onFailure, 50*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)

	// Keep recording TX to keep it active
	go func() {
		for i := 0; i < 10; i++ {
			mon.RecordTx()
			time.Sleep(30 * time.Millisecond)
		}
	}()

	// Don't record RX, let it become idle
	time.Sleep(200 * time.Millisecond)

	mon.Close()

	// Should trigger failure when RX is idle but TX is active
	if !called {
		t.Error("onFailure should be called when RX is idle but TX is active")
	}
}

// TestConnectivityMonitor_OnlyTxIdle tests when TX is idle but RX is active
func TestConnectivityMonitor_OnlyTxIdle(t *testing.T) {
	called := false
	onFailure := func() {
		called = true
	}

	// Use very short timeouts for testing
	mon := NewConnectivityMonitorWithTimeouts(onFailure, 50*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)

	// Keep recording RX to keep it active
	go func() {
		for i := 0; i < 10; i++ {
			mon.RecordRx()
			time.Sleep(30 * time.Millisecond)
		}
	}()

	// Don't record TX, let it become idle
	time.Sleep(200 * time.Millisecond)

	mon.Close()

	// Should not trigger failure when TX is idle but RX is active (this is normal)
	if called {
		t.Error("onFailure should not be called when TX is idle but RX is active")
	}
}

// TestConnectivityMonitor_AsymmetricTraffic tests scenario 2: sending but not receiving
func TestConnectivityMonitor_AsymmetricTraffic(t *testing.T) {
	callbackChan := make(chan bool, 1)
	onFailure := func() {
		callbackChan <- true
	}

	// Use short timeouts: checkInterval=30ms, idleTimeout=150ms, asymmetricTimeout=60ms
	mon := NewConnectivityMonitorWithTimeouts(onFailure, 30*time.Millisecond, 150*time.Millisecond, 60*time.Millisecond)

	// Wait a bit for monitor to start
	time.Sleep(10 * time.Millisecond)

	// Set RX time to be old (beyond asymmetricTimeout)
	oldRxTime := time.Now().Add(-100 * time.Millisecond)
	mon.lastRxTime.Store(oldRxTime)

	// Set TX time to be recent (within asymmetricTimeout)
	recentTxTime := time.Now().Add(-10 * time.Millisecond)
	mon.lastTxTime.Store(recentTxTime)

	// Wait for callback
	select {
	case <-callbackChan:
		// Success - callback was called
	case <-time.After(200 * time.Millisecond):
		t.Error("onFailure should be called for asymmetric traffic (TX recent, RX old)")
	}

	mon.Close()
}

// TestConnectivityMonitor_CompleteIdleScenario1 tests scenario 1 (both TX and RX idle, no failure)
func TestConnectivityMonitor_CompleteIdleScenario1(t *testing.T) {
	callbackChan := make(chan bool, 1)
	onFailure := func() {
		callbackChan <- true
	}

	// Use short timeouts: checkInterval=30ms, idleTimeout=100ms, asymmetricTimeout=60ms
	mon := NewConnectivityMonitorWithTimeouts(onFailure, 30*time.Millisecond, 100*time.Millisecond, 60*time.Millisecond)

	// Wait a bit for monitor to start
	time.Sleep(10 * time.Millisecond)

	// Set both RX and TX time to be old (beyond idleTimeout)
	oldTime := time.Now().Add(-150 * time.Millisecond)
	mon.lastRxTime.Store(oldTime)
	mon.lastTxTime.Store(oldTime)

	// Wait to ensure checkConnectivity runs
	time.Sleep(100 * time.Millisecond)

	// Verify callback was NOT called (scenario 1 should not trigger failure)
	select {
	case <-callbackChan:
		t.Error("onFailure should NOT be called for scenario 1 (complete idle)")
	case <-time.After(50 * time.Millisecond):
		// Success - callback was not called
	}

	mon.Close()
}

// TestConnectivityMonitor_LongIdleRxRecentTxScenario3 tests scenario 3
func TestConnectivityMonitor_LongIdleRxRecentTxScenario3(t *testing.T) {
	callbackChan := make(chan bool, 1)
	onFailure := func() {
		callbackChan <- true
	}

	// Use short timeouts: checkInterval=30ms, idleTimeout=100ms, asymmetricTimeout=60ms
	mon := NewConnectivityMonitorWithTimeouts(onFailure, 30*time.Millisecond, 100*time.Millisecond, 60*time.Millisecond)

	// Wait a bit for monitor to start
	time.Sleep(10 * time.Millisecond)

	// Set RX time to be very old (beyond idleTimeout)
	oldRxTime := time.Now().Add(-150 * time.Millisecond)
	mon.lastRxTime.Store(oldRxTime)

	// Set TX time to be very recent (within checkInterval)
	recentTxTime := time.Now().Add(-5 * time.Millisecond)
	mon.lastTxTime.Store(recentTxTime)

	// Wait for callback
	select {
	case <-callbackChan:
		// Success - callback was called
	case <-time.After(200 * time.Millisecond):
		t.Error("onFailure should be called for scenario 3 (recent TX, very old RX)")
	}

	mon.Close()
}
