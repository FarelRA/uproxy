// Package integration provides integration tests for uproxy components.
package integration

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"uproxy/internal/network"
	"uproxy/internal/tun"
	"uproxy/internal/validation"
)

// TestTUNDevicePacketFlow tests the integration between TUN device and packet routing
func TestTUNDevicePacketFlow(t *testing.T) {
	// Create TUN manager
	manager, err := tun.NewTUNManager(&tun.Config{}, "tun0", false)
	if err != nil {
		t.Fatalf("Failed to create TUN manager: %v", err)
	}
	if manager == nil {
		t.Fatal("TUN manager is nil")
	}

	// Register a test client
	clientIP := manager.AllocateIP()
	if clientIP == "" {
		t.Fatal("Failed to allocate IP")
	}

	// Verify IP was allocated
	if clientIP != "10.0.0.2" {
		t.Errorf("Expected IP 10.0.0.2, got %s", clientIP)
	}

	// Unregister client
	manager.UnregisterClient(clientIP)
}

// TestValidationWithNetworkDiagnostics tests validation and diagnostics integration
func TestValidationWithNetworkDiagnostics(t *testing.T) {
	// Test IP validation
	validIP := "192.168.1.1"
	if !validation.ValidateIPAddress(validIP) {
		t.Error("Valid IP rejected")
	}

	invalidIP := "999.999.999.999"
	if validation.ValidateIPAddress(invalidIP) {
		t.Error("Invalid IP accepted")
	}

	// Test diagnostics initialization
	diag := network.NewDiagnostics("example.com:22", slog.Default())
	if diag == nil {
		t.Fatal("Failed to create diagnostics")
	}

	// Test diagnostics with context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result := diag.DiagnoseFailure(ctx)
	if result.FailureType == network.FailureNone {
		t.Error("Expected failure type to be set")
	}
}

// TestPacketValidationFlow tests packet validation integration
func TestPacketValidationFlow(t *testing.T) {
	// Test IPv4 packet validation
	ipv4Packet := []byte{
		0x45, 0x00, 0x00, 0x3c, // Version, IHL, TOS, Total Length
		0x1c, 0x46, 0x40, 0x00, // ID, Flags, Fragment Offset
		0x40, 0x06, 0xb1, 0xe6, // TTL, Protocol, Checksum
		0xc0, 0xa8, 0x00, 0x01, // Source IP
		0xc0, 0xa8, 0x00, 0x02, // Dest IP
	}

	if !validation.ValidateIPv4Packet(ipv4Packet) {
		t.Error("Valid IPv4 packet rejected")
	}

	// Test IPv6 packet validation
	ipv6Packet := []byte{
		0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
		0x00, 0x14, 0x06, 0x40, // Payload Length, Next Header, Hop Limit
		0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source IP (first 8 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source IP (last 8 bytes)
		0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dest IP (first 8 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // Dest IP (last 8 bytes)
	}

	if !validation.ValidateIPv6Packet(ipv6Packet) {
		t.Error("Valid IPv6 packet rejected")
	}
}

// TestSOCKS5ValidationFlow tests SOCKS5 validation integration
func TestSOCKS5ValidationFlow(t *testing.T) {
	// Test SOCKS5 version validation
	if !validation.ValidateSOCKS5Version(0x05) {
		t.Error("Valid SOCKS5 version rejected")
	}

	if validation.ValidateSOCKS5Version(0x04) {
		t.Error("Invalid SOCKS5 version accepted")
	}

	// Test address type validation
	if !validation.ValidateSOCKS5AddressType(0x01) {
		t.Error("Valid address type rejected")
	}

	if validation.ValidateSOCKS5AddressType(0x99) {
		t.Error("Invalid address type accepted")
	}

	// Test command validation
	if !validation.ValidateSOCKS5Command(0x01) {
		t.Error("Valid command rejected")
	}

	if validation.ValidateSOCKS5Command(0x99) {
		t.Error("Invalid command accepted")
	}
}

// TestNetworkResolverIntegration tests IP resolution integration
func TestNetworkResolverIntegration(t *testing.T) {
	// Test extracting host from address
	host := network.ExtractHost("example.com:8080")
	if host != "example.com" {
		t.Errorf("Expected 'example.com', got '%s'", host)
	}

	host = network.ExtractHost("192.168.1.1:9090")
	if host != "192.168.1.1" {
		t.Errorf("Expected '192.168.1.1', got '%s'", host)
	}

	// Test with IPv6
	host = network.ExtractHost("[::1]:8080")
	if host != "::1" {
		t.Errorf("Expected '::1', got '%s'", host)
	}
}

// TestPortValidation tests port validation integration
func TestPortValidation(t *testing.T) {
	// Test valid ports
	validPorts := []int{1, 80, 443, 8080, 65535}
	for _, port := range validPorts {
		if !validation.ValidatePort(port) {
			t.Errorf("Valid port %d rejected", port)
		}
	}

	// Test invalid ports
	invalidPorts := []int{0, -1, 65536, 100000}
	for _, port := range invalidPorts {
		if validation.ValidatePort(port) {
			t.Errorf("Invalid port %d accepted", port)
		}
	}
}

// TestTUNManagerConcurrency tests concurrent operations on TUN manager
func TestTUNManagerConcurrency(t *testing.T) {
	manager, err := tun.NewTUNManager(&tun.Config{}, "tun0", false)
	if err != nil {
		t.Fatalf("Failed to create TUN manager: %v", err)
	}
	if manager == nil {
		t.Fatal("TUN manager is nil")
	}

	// Allocate multiple IPs concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			ip := manager.AllocateIP()
			if ip == "" {
				t.Error("Failed to allocate IP")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestDiagnosticsWithTimeout tests diagnostics with context timeout
func TestDiagnosticsWithTimeout(t *testing.T) {
	diag := network.NewDiagnostics("example.com:22", slog.Default())
	if diag == nil {
		t.Fatal("Failed to create diagnostics")
	}

	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for context to timeout
	time.Sleep(10 * time.Millisecond)

	result := diag.DiagnoseFailure(ctx)

	// Should still return a result even with timeout
	if result.FailureType == network.FailureNone {
		t.Error("Expected failure type to be set even with timeout")
	}
}

// TestAddressValidationIntegration tests address validation with net package
func TestAddressValidationIntegration(t *testing.T) {
	// Test valid IPv4
	ip := net.ParseIP("192.168.1.1")
	if ip == nil {
		t.Error("Failed to parse valid IPv4")
	}

	if !validation.ValidateIPAddress(ip.String()) {
		t.Error("Valid IPv4 rejected")
	}

	// Test valid IPv6
	ip = net.ParseIP("fd00::1")
	if ip == nil {
		t.Error("Failed to parse valid IPv6")
	}

	if !validation.ValidateIPAddress(ip.String()) {
		t.Error("Valid IPv6 rejected")
	}
}
