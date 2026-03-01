package main

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"uproxy/internal/config"
)

// TestConnectionManager_GetSSHClient tests thread-safe access to SSH client
func TestConnectionManager_GetSSHClient(t *testing.T) {
	cfg := &config.ClientConfig{}
	cm := newConnectionManager(cfg, nil)

	// Test nil client
	if client := cm.getSSHClient(); client != nil {
		t.Error("Expected nil client initially")
	}

	// Test concurrent reads
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cm.getSSHClient()
		}()
	}
	wg.Wait()
}

// TestConnectionManager_CloseConnection tests thread-safe connection closing
func TestConnectionManager_CloseConnection(t *testing.T) {
	cfg := &config.ClientConfig{}
	cm := newConnectionManager(cfg, nil)

	// Test closing nil connection (should not panic)
	cm.closeConnection()

	// Test concurrent closes
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cm.closeConnection()
		}()
	}
	wg.Wait()
}

// TestConnectionManager_ConcurrentAccess tests concurrent read/write operations
func TestConnectionManager_ConcurrentAccess(t *testing.T) {
	cfg := &config.ClientConfig{}
	cm := newConnectionManager(cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = cm.getSSHClient()
					time.Sleep(1 * time.Millisecond)
				}
			}
		}()
	}

	// Concurrent closers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					cm.closeConnection()
					time.Sleep(10 * time.Millisecond)
				}
			}
		}()
	}

	<-ctx.Done()
	wg.Wait()
}

// TestValidateMode tests mode validation logic
func TestValidateMode(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.ClientConfig
		wantErr bool
	}{
		{
			name:    "valid socks5 mode with listen",
			cfg:     &config.ClientConfig{Mode: "socks5", ListenAddr: ":1080"},
			wantErr: false,
		},
		{
			name:    "socks5 mode without listen",
			cfg:     &config.ClientConfig{Mode: "socks5"},
			wantErr: true, // socks5 requires --listen
		},
		{
			name:    "tun mode requires root",
			cfg:     &config.ClientConfig{Mode: "tun"},
			wantErr: os.Geteuid() != 0, // Expect error if not root
		},
		{
			name:    "valid auto mode",
			cfg:     &config.ClientConfig{Mode: "auto"},
			wantErr: false,
		},
		{
			name:    "invalid mode",
			cfg:     &config.ClientConfig{Mode: "invalid"},
			wantErr: true,
		},
		{
			name:    "empty mode",
			cfg:     &config.ClientConfig{Mode: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMode(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateMode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNewConnectionManager tests connectionManager initialization
func TestNewConnectionManager(t *testing.T) {
	cfg := &config.ClientConfig{
		ServerAddr: "test:1234",
	}

	// Create a dummy signer (nil is acceptable for this test)
	cm := newConnectionManager(cfg, nil)

	if cm == nil {
		t.Fatal("Expected non-nil connectionManager")
	}

	if cm.cfg != cfg {
		t.Error("Config not properly set")
	}

	if cm.getSSHClient() != nil {
		t.Error("Expected nil SSH client initially")
	}
}

// TestConnectionManager_WaitForDisconnection tests disconnection detection
func TestConnectionManager_WaitForDisconnection(t *testing.T) {
	cfg := &config.ClientConfig{}
	cm := newConnectionManager(cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Test with nil client (should return immediately)
	done := make(chan struct{})
	go func() {
		cm.waitForDisconnection(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Expected - should return immediately with nil client
	case <-time.After(200 * time.Millisecond):
		t.Error("waitForDisconnection did not return with nil client")
	}
}

// mockSSHClient is a minimal mock for testing
type mockSSHClient struct {
	waitCh chan struct{}
}

func (m *mockSSHClient) Wait() error {
	<-m.waitCh
	return nil
}

func (m *mockSSHClient) Close() error {
	select {
	case <-m.waitCh:
		// Already closed
	default:
		close(m.waitCh)
	}
	return nil
}

// TestConnectionManager_StateTransitions tests connection state management
func TestConnectionManager_StateTransitions(t *testing.T) {
	cfg := &config.ClientConfig{}
	cm := newConnectionManager(cfg, nil)

	// Initial state: no connection
	if cm.getSSHClient() != nil {
		t.Error("Expected nil client in initial state")
	}

	// After close: still no connection
	cm.closeConnection()
	if cm.getSSHClient() != nil {
		t.Error("Expected nil client after closing nil connection")
	}

	// Multiple closes should be safe
	cm.closeConnection()
	cm.closeConnection()
	if cm.getSSHClient() != nil {
		t.Error("Expected nil client after multiple closes")
	}
}

// BenchmarkConnectionManager_GetSSHClient benchmarks thread-safe client access
func BenchmarkConnectionManager_GetSSHClient(b *testing.B) {
	cfg := &config.ClientConfig{}
	cm := newConnectionManager(cfg, nil)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cm.getSSHClient()
		}
	})
}

// BenchmarkConnectionManager_CloseConnection benchmarks thread-safe close
func BenchmarkConnectionManager_CloseConnection(b *testing.B) {
	cfg := &config.ClientConfig{}
	cm := newConnectionManager(cfg, nil)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cm.closeConnection()
		}
	})
}

// TestConnectionManager_HandleConnectivityFailure tests failure handling
func TestConnectionManager_HandleConnectivityFailure(t *testing.T) {
	cfg := &config.ClientConfig{
		ServerAddr: "test:1234",
	}
	cm := newConnectionManager(cfg, nil)

	// Test that handleConnectivityFailure doesn't panic with nil diagnostics
	// This is a basic smoke test - the actual failure handler requires
	// diagnostics to be set up, which happens in establishConnection.
	// For now, just verify the connectionManager can be created without panicking.
	if cm.diagnostics != nil {
		t.Error("Expected nil diagnostics before establishConnection")
	}
}
