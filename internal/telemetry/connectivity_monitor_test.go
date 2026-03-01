package telemetry

import (
	"testing"
	"time"
)

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
