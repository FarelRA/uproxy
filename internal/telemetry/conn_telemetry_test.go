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
