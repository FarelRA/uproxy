package network

import (
	"net"
	"testing"
)

func TestExtractHost(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{"Host with port", "example.com:8080", "example.com"},
		{"IPv4 with port", "192.168.1.1:443", "192.168.1.1"},
		{"IPv6 with port", "[::1]:8080", "::1"},
		{"Host without port", "example.com", "example.com"},
		{"IPv4 without port", "192.168.1.1", "192.168.1.1"},
		{"IPv6 without port", "::1", "::1"},
		{"Localhost with port", "localhost:3000", "localhost"},
		{"Localhost without port", "localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractHost(tt.addr)
			if result != tt.expected {
				t.Errorf("ExtractHost(%q) = %q, want %q", tt.addr, result, tt.expected)
			}
		})
	}
}

func TestResolveToIPv4AndIPv6(t *testing.T) {
	tests := []struct {
		name         string
		serverAddr   string
		expectIPv4   bool
		expectIPv6   bool
		expectError  bool
		skipIfNoIPv6 bool
	}{
		{
			name:        "IPv4 address with port",
			serverAddr:  "8.8.8.8:53",
			expectIPv4:  true,
			expectIPv6:  false,
			expectError: false,
		},
		{
			name:        "IPv4 address without port",
			serverAddr:  "1.1.1.1",
			expectIPv4:  true,
			expectIPv6:  false,
			expectError: false,
		},
		{
			name:        "IPv6 address with port",
			serverAddr:  "[2001:4860:4860::8888]:53",
			expectIPv4:  false,
			expectIPv6:  true,
			expectError: false,
		},
		{
			name:        "IPv6 address without port",
			serverAddr:  "2001:4860:4860::8888",
			expectIPv4:  false,
			expectIPv6:  true,
			expectError: false,
		},
		{
			name:        "Localhost hostname",
			serverAddr:  "localhost:8080",
			expectIPv4:  true,
			expectIPv6:  false,
			expectError: false,
		},
		{
			name:         "Google DNS hostname",
			serverAddr:   "dns.google:443",
			expectIPv4:   true,
			expectIPv6:   true,
			expectError:  false,
			skipIfNoIPv6: true,
		},
		{
			name:        "Invalid hostname",
			serverAddr:  "invalid.nonexistent.domain.test:443",
			expectIPv4:  false,
			expectIPv6:  false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipv4, ipv6, err := ResolveToIPv4AndIPv6(tt.serverAddr)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if tt.expectIPv4 && ipv4 == "" {
				t.Error("Expected IPv4 address but got empty string")
			}

			if !tt.expectIPv4 && ipv4 != "" {
				t.Errorf("Expected no IPv4 address but got %q", ipv4)
			}

			if tt.expectIPv6 && ipv6 == "" {
				if tt.skipIfNoIPv6 {
					t.Skip("IPv6 not available in this environment")
				} else {
					t.Error("Expected IPv6 address but got empty string")
				}
			}

			if !tt.expectIPv6 && ipv6 != "" {
				t.Errorf("Expected no IPv6 address but got %q", ipv6)
			}
		})
	}
}

func TestResolveToIPv4AndIPv6_EdgeCases(t *testing.T) {
	// Test with empty string
	_, _, err := ResolveToIPv4AndIPv6("")
	if err == nil {
		t.Error("Expected error for empty address")
	}

	// Test with just a port
	_, _, err = ResolveToIPv4AndIPv6(":8080")
	if err == nil {
		t.Error("Expected error for address with only port")
	}
}

func BenchmarkExtractHost(b *testing.B) {
	addr := "example.com:8080"
	for i := 0; i < b.N; i++ {
		_ = ExtractHost(addr)
	}
}

func BenchmarkResolveToIPv4AndIPv6_IP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = ResolveToIPv4AndIPv6("8.8.8.8:53")
	}
}

func BenchmarkResolveToIPv4AndIPv6_Hostname(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = ResolveToIPv4AndIPv6("localhost:8080")
	}
}

// mockDNSResolver is a mock implementation of dnsResolver for testing
type mockDNSResolver struct {
	lookupIPFunc func(host string) ([]net.IP, error)
	parseIPFunc  func(s string) net.IP
}

func (m *mockDNSResolver) LookupIP(host string) ([]net.IP, error) {
	if m.lookupIPFunc != nil {
		return m.lookupIPFunc(host)
	}
	return nil, nil
}

func (m *mockDNSResolver) ParseIP(s string) net.IP {
	if m.parseIPFunc != nil {
		return m.parseIPFunc(s)
	}
	return net.ParseIP(s)
}

func TestResolveToIPv4AndIPv6_NoIPsReturned(t *testing.T) {
	// Save original resolver and restore after test
	originalResolver := resolver
	defer func() { resolver = originalResolver }()

	// Mock resolver that returns empty IP slice
	resolver = &mockDNSResolver{
		lookupIPFunc: func(host string) ([]net.IP, error) {
			return []net.IP{}, nil
		},
		parseIPFunc: func(s string) net.IP {
			return nil // Not an IP, force lookup
		},
	}

	_, _, err := ResolveToIPv4AndIPv6("example.com:443")
	if err == nil {
		t.Error("Expected error when no IPs are returned")
	}
	if err.Error() != "no IPs found for server address" {
		t.Errorf("Unexpected error message: %v", err)
	}
}
