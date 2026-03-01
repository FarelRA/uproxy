package uproxy

import (
	"errors"
	"net"
	"runtime"
	"testing"
)

// mockNetworkInterface for testing
type mockNetworkInterface struct {
	addrs []net.Addr
	err   error
}

func (m *mockNetworkInterface) Addrs() ([]net.Addr, error) {
	return m.addrs, m.err
}

func TestIsRoot(t *testing.T) {
	result := IsRoot()
	if runtime.GOOS == "windows" {
		if result {
			t.Error("Expected IsRoot to return false on Windows")
		}
	}
	// On Unix, we can't reliably test this without actually being root
	// Just verify it returns a boolean
	_ = result
}

func TestFirstIPv4OfInterface(t *testing.T) {
	// Test with non-existent interface
	_, err := FirstIPv4OfInterface("nonexistent999")
	if err == nil {
		t.Error("Expected error for non-existent interface")
	}

	// Test with loopback interface (should exist on all systems)
	loopbackName := "lo"
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		loopbackName = "lo0"
	}

	ip, err := FirstIPv4OfInterface(loopbackName)
	if err != nil {
		// Loopback might not exist or have IPv4, skip
		t.Skipf("Loopback interface %s not available or no IPv4: %v", loopbackName, err)
	}
	if ip == nil {
		t.Error("Expected non-nil IP")
	}
	if ip.To4() == nil {
		t.Error("Expected IPv4 address")
	}
}

func TestFirstIPv6OfInterface(t *testing.T) {
	// Test with non-existent interface
	_, err := FirstIPv6OfInterface("nonexistent999")
	if err == nil {
		t.Error("Expected error for non-existent interface")
	}

	// Test with loopback - may or may not have IPv6
	loopbackName := "lo"
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		loopbackName = "lo0"
	}

	ip, err := FirstIPv6OfInterface(loopbackName)
	if err != nil {
		// IPv6 might not be configured, that's okay
		t.Logf("No IPv6 on %s: %v", loopbackName, err)
		return
	}
	if ip == nil {
		t.Error("Expected non-nil IP")
	}
	if ip.To4() != nil {
		t.Error("Expected IPv6 address, got IPv4")
	}
}

func TestFirstIPOfInterface(t *testing.T) {
	// Test with non-existent interface
	_, err := FirstIPOfInterface("nonexistent999")
	if err == nil {
		t.Error("Expected error for non-existent interface")
	}

	// Test with loopback interface
	loopbackName := "lo"
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		loopbackName = "lo0"
	}

	ip, err := FirstIPOfInterface(loopbackName)
	if err != nil {
		t.Skipf("Loopback interface %s not available: %v", loopbackName, err)
	}
	if ip == nil {
		t.Error("Expected non-nil IP")
	}
}

func TestGetInterfaceIPs(t *testing.T) {
	// Test with non-existent interface
	_, _, err := GetInterfaceIPs("nonexistent999")
	if err == nil {
		t.Error("Expected error for non-existent interface")
	}

	// Test with loopback interface
	loopbackName := "lo"
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		loopbackName = "lo0"
	}

	ipv4, ipv6, err := GetInterfaceIPs(loopbackName)
	if err != nil {
		t.Skipf("Loopback interface %s not available: %v", loopbackName, err)
	}

	// At least one should be non-nil
	if ipv4 == nil && ipv6 == nil {
		t.Error("Expected at least one IP address")
	}

	if ipv4 != nil && ipv4.To4() == nil {
		t.Error("IPv4 address is not valid IPv4")
	}

	if ipv6 != nil && ipv6.To4() != nil {
		t.Error("IPv6 address is actually IPv4")
	}
}

func TestBindAddrForInterface(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		iface     string
		wantErr   bool
		skipCheck bool
	}{
		{
			name:      "no interface specified",
			addr:      ":8080",
			iface:     "",
			wantErr:   false,
			skipCheck: false,
		},
		{
			name:      "invalid address",
			addr:      "invalid",
			iface:     "eth0",
			wantErr:   true,
			skipCheck: false,
		},
		{
			name:      "wildcard with interface",
			addr:      "0.0.0.0:8080",
			iface:     "lo",
			wantErr:   false,
			skipCheck: true, // Skip because interface might not exist
		},
		{
			name:      "specific IP with interface",
			addr:      "192.168.1.1:8080",
			iface:     "eth0",
			wantErr:   false,
			skipCheck: false,
		},
		{
			name:      "IPv6 wildcard",
			addr:      "[::]:8080",
			iface:     "lo",
			wantErr:   false,
			skipCheck: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BindAddrForInterface(tt.addr, tt.iface)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if tt.skipCheck {
				// Just verify it doesn't panic
				_ = result
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result == "" {
				t.Error("Expected non-empty result")
			}
		})
	}
}

func TestOptimizeUDPConn(t *testing.T) {
	// Create a UDP connection
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	// Test with positive buffer size
	OptimizeUDPConn(conn, 65536)

	// Test with zero buffer size (should be no-op)
	OptimizeUDPConn(conn, 0)

	// Test with negative buffer size (should be no-op)
	OptimizeUDPConn(conn, -1)
}

func TestBindAddrForInterface_EmptyPort(t *testing.T) {
	// Test with empty port wildcard
	loopbackName := "lo"
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		loopbackName = "lo0"
	}

	result, err := BindAddrForInterface(":9999", loopbackName)
	if err != nil {
		t.Skipf("Loopback interface not available: %v", err)
	}
	if result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestBindAddrForInterface_NonExistentInterface(t *testing.T) {
	_, err := BindAddrForInterface("0.0.0.0:8080", "nonexistent999")
	if err == nil {
		t.Error("Expected error for non-existent interface")
	}
}

func TestIsRoot_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping Unix-specific test on Windows")
	}

	// Just call it to ensure the Unix path is executed
	result := IsRoot()
	// We can't control whether we're root or not, but we can verify it returns a boolean
	_ = result
}

// Test error paths using mocked interface
func TestFirstIPv4OfInterface_AddrsError(t *testing.T) {
	// Save original function
	originalFunc := interfaceByNameFunc
	defer func() { interfaceByNameFunc = originalFunc }()

	// Mock interfaceByNameFunc to return an interface that errors on Addrs()
	interfaceByNameFunc = func(name string) (networkInterface, error) {
		return &mockNetworkInterface{
			err: errors.New("mock addrs error"),
		}, nil
	}

	_, err := FirstIPv4OfInterface("test")
	if err == nil {
		t.Error("Expected error from Addrs()")
	}
	if !contains(err.Error(), "failed to get addresses") {
		t.Errorf("Expected 'failed to get addresses' error, got: %v", err)
	}
}

func TestFirstIPv6OfInterface_AddrsError(t *testing.T) {
	// Save original function
	originalFunc := interfaceByNameFunc
	defer func() { interfaceByNameFunc = originalFunc }()

	// Mock interfaceByNameFunc to return an interface that errors on Addrs()
	interfaceByNameFunc = func(name string) (networkInterface, error) {
		return &mockNetworkInterface{
			err: errors.New("mock addrs error"),
		}, nil
	}

	_, err := FirstIPv6OfInterface("test")
	if err == nil {
		t.Error("Expected error from Addrs()")
	}
	if !contains(err.Error(), "failed to get addresses") {
		t.Errorf("Expected 'failed to get addresses' error, got: %v", err)
	}
}

func TestGetInterfaceIPs_AddrsError(t *testing.T) {
	// Save original function
	originalFunc := interfaceByNameFunc
	defer func() { interfaceByNameFunc = originalFunc }()

	// Mock interfaceByNameFunc to return an interface that errors on Addrs()
	interfaceByNameFunc = func(name string) (networkInterface, error) {
		return &mockNetworkInterface{
			err: errors.New("mock addrs error"),
		}, nil
	}

	_, _, err := GetInterfaceIPs("test")
	if err == nil {
		t.Error("Expected error from Addrs()")
	}
	if !contains(err.Error(), "failed to get addresses") {
		t.Errorf("Expected 'failed to get addresses' error, got: %v", err)
	}
}

func TestFirstIPv4OfInterface_NoIPv4Found(t *testing.T) {
	// Save original function
	originalFunc := interfaceByNameFunc
	defer func() { interfaceByNameFunc = originalFunc }()

	// Mock interfaceByNameFunc to return only IPv6 addresses
	interfaceByNameFunc = func(name string) (networkInterface, error) {
		_, ipnet, _ := net.ParseCIDR("2001:db8::1/64")
		return &mockNetworkInterface{
			addrs: []net.Addr{ipnet},
		}, nil
	}

	_, err := FirstIPv4OfInterface("test")
	if err == nil {
		t.Error("Expected error when no IPv4 found")
	}
	if !contains(err.Error(), "no IPv4 address found") {
		t.Errorf("Expected 'no IPv4 address found' error, got: %v", err)
	}
}

func TestFirstIPv6OfInterface_NoIPv6Found(t *testing.T) {
	// Save original function
	originalFunc := interfaceByNameFunc
	defer func() { interfaceByNameFunc = originalFunc }()

	// Mock interfaceByNameFunc to return only IPv4 addresses
	interfaceByNameFunc = func(name string) (networkInterface, error) {
		_, ipnet, _ := net.ParseCIDR("192.168.1.1/24")
		return &mockNetworkInterface{
			addrs: []net.Addr{ipnet},
		}, nil
	}

	_, err := FirstIPv6OfInterface("test")
	if err == nil {
		t.Error("Expected error when no IPv6 found")
	}
	if !contains(err.Error(), "no IPv6 address found") {
		t.Errorf("Expected 'no IPv6 address found' error, got: %v", err)
	}
}

func TestGetInterfaceIPs_NoAddresses(t *testing.T) {
	// Save original function
	originalFunc := interfaceByNameFunc
	defer func() { interfaceByNameFunc = originalFunc }()

	// Mock interfaceByNameFunc to return empty address list
	interfaceByNameFunc = func(name string) (networkInterface, error) {
		return &mockNetworkInterface{
			addrs: []net.Addr{},
		}, nil
	}

	_, _, err := GetInterfaceIPs("test")
	if err == nil {
		t.Error("Expected error when no addresses found")
	}
	if !contains(err.Error(), "no IP addresses found") {
		t.Errorf("Expected 'no IP addresses found' error, got: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
