package quictransport

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestClient_Creation(t *testing.T) {
	// Test that Client can be created with valid parameters
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	quicConfig := NewQUICConfig(nil)

	client := NewClient(udpAddr, tlsConfig, quicConfig)
	if client == nil {
		t.Fatal("NewClient returned nil")
	}

	// Verify client is not connected initially
	if client.IsConnected() {
		t.Error("New client should not be connected")
	}
}

func TestClient_ConnectionState(t *testing.T) {
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	quicConfig := NewQUICConfig(nil)

	client := NewClient(udpAddr, tlsConfig, quicConfig)

	// Test initial state
	if client.IsConnected() {
		t.Error("Client should not be connected initially")
	}

	conn := client.GetConnection()
	if conn != nil {
		t.Error("GetConnection should return nil when not connected")
	}
}

func TestClient_WaitForDisconnection(t *testing.T) {
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	quicConfig := NewQUICConfig(nil)

	client := NewClient(udpAddr, tlsConfig, quicConfig)

	// WaitForDisconnection should return immediately if not connected
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		client.WaitForDisconnection(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Expected - should return quickly
	case <-time.After(200 * time.Millisecond):
		t.Error("WaitForDisconnection blocked unexpectedly")
	}
}

func TestClient_Close(t *testing.T) {
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	quicConfig := NewQUICConfig(nil)

	client := NewClient(udpAddr, tlsConfig, quicConfig)

	// Close should not panic even if not connected
	err := client.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Multiple closes should be safe
	err = client.Close()
	if err != nil {
		t.Errorf("Second Close() returned error: %v", err)
	}
}

// Note: Full integration tests for Connect(), OpenTCPStream(), OpenUDPStream(),
// and OpenTUNStream() require a running QUIC server and are tested in the
// cmd/uproxy integration tests.
