package quictransport

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestServer_Creation(t *testing.T) {
	// Test that Server can be created with valid parameters
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{},
	}

	quicConfig := NewQUICConfig(nil)

	server := NewServer(udpAddr, tlsConfig, quicConfig)
	if server == nil {
		t.Fatal("NewServer returned nil")
	}
}

func TestServer_ConnectionTracking(t *testing.T) {
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{}}
	quicConfig := NewQUICConfig(nil)

	server := NewServer(udpAddr, tlsConfig, quicConfig)

	// Test initial connection count
	count := server.ActiveConnectionCount()
	if count != 0 {
		t.Errorf("ActiveConnectionCount() = %d, want 0", count)
	}
}

func TestServer_Close(t *testing.T) {
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{}}
	quicConfig := NewQUICConfig(nil)

	server := NewServer(udpAddr, tlsConfig, quicConfig)

	// Close should not panic even if not listening
	err := server.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Multiple closes should be safe
	err = server.Close()
	if err != nil {
		t.Errorf("Second Close() returned error: %v", err)
	}
}

func TestServer_CloseAllConnections(t *testing.T) {
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{}}
	quicConfig := NewQUICConfig(nil)

	server := NewServer(udpAddr, tlsConfig, quicConfig)

	// CloseAllConnections should not panic with no connections
	server.CloseAllConnections(quic.ApplicationErrorCode(0), "test shutdown")

	// Verify count is still 0
	if count := server.ActiveConnectionCount(); count != 0 {
		t.Errorf("ActiveConnectionCount() = %d after CloseAllConnections, want 0", count)
	}
}

// Note: Full integration tests for Listen(), Accept(), and AcceptStream()
// require actual QUIC connections and are tested in the cmd/uproxy
// integration tests.
