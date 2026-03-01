package tun

import (
	"strings"
	"testing"
)

func TestNewIPAllocator(t *testing.T) {
	tests := []struct {
		name       string
		serverIPv4 string
		netmask    string
		serverIPv6 string
		expectIPv4 bool
		expectIPv6 bool
	}{
		{
			name:       "IPv4 only",
			serverIPv4: "10.0.0.1",
			netmask:    "255.255.255.0",
			serverIPv6: "",
			expectIPv4: true,
			expectIPv6: false,
		},
		{
			name:       "IPv4 and IPv6",
			serverIPv4: "10.0.0.1",
			netmask:    "255.255.255.0",
			serverIPv6: "fd00::1/64",
			expectIPv4: true,
			expectIPv6: true,
		},
		{
			name:       "IPv6 only",
			serverIPv4: "",
			netmask:    "",
			serverIPv6: "fd00::1/64",
			expectIPv4: false,
			expectIPv6: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocator := NewIPAllocator(tt.serverIPv4, tt.netmask, tt.serverIPv6)

			if allocator == nil {
				t.Fatal("NewIPAllocator returned nil")
			}

			hasIPv4 := allocator.ipv4Network != nil
			hasIPv6 := allocator.ipv6Network != nil

			if hasIPv4 != tt.expectIPv4 {
				t.Errorf("IPv4 config: got %v, want %v", hasIPv4, tt.expectIPv4)
			}

			if hasIPv6 != tt.expectIPv6 {
				t.Errorf("IPv6 config: got %v, want %v", hasIPv6, tt.expectIPv6)
			}
		})
	}
}

func TestAllocateIP_IPv4(t *testing.T) {
	allocator := NewIPAllocator("10.0.0.1", "255.255.255.0", "")

	// Allocate first IP
	ipv4, ipv6, err := allocator.AllocateIP()
	if err != nil {
		t.Fatalf("AllocateIP failed: %v", err)
	}

	if ipv4 == "" {
		t.Error("Expected IPv4 address, got empty string")
	}

	if ipv6 != "" {
		t.Errorf("Expected no IPv6 address, got %s", ipv6)
	}

	// Verify IP is in correct range
	if !strings.HasPrefix(ipv4, "10.0.0.") {
		t.Errorf("IPv4 address %s not in expected network 10.0.0.0/24", ipv4)
	}

	// Verify IP is not the server IP
	if ipv4 == "10.0.0.1" {
		t.Error("Allocated IP should not be the server IP")
	}

	// Verify IP is marked as held
	if !allocator.heldIPv4[ipv4] {
		t.Error("Allocated IP not marked as held")
	}
}

func TestAllocateIP_IPv6(t *testing.T) {
	allocator := NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64")

	ipv4, ipv6, err := allocator.AllocateIP()
	if err != nil {
		t.Fatalf("AllocateIP failed: %v", err)
	}

	if ipv4 == "" {
		t.Error("Expected IPv4 address, got empty string")
	}

	if ipv6 == "" {
		t.Error("Expected IPv6 address, got empty string")
	}

	// Verify IPv6 is in correct format
	if !strings.HasPrefix(ipv6, "fd00:") {
		t.Errorf("IPv6 address %s not in expected network fd00::/64", ipv6)
	}

	// Verify IPv6 is not the server IP
	if ipv6 == "fd00::1/64" {
		t.Error("Allocated IPv6 should not be the server IP")
	}

	// Verify IPs are marked as held
	if !allocator.heldIPv6[ipv6] {
		t.Error("Allocated IPv6 not marked as held")
	}
}

func TestAllocateIP_MultipleAllocations(t *testing.T) {
	allocator := NewIPAllocator("10.0.0.1", "255.255.255.0", "")

	allocated := make(map[string]bool)

	// Allocate 50 IPs
	for i := 0; i < 50; i++ {
		ipv4, _, err := allocator.AllocateIP()
		if err != nil {
			t.Fatalf("AllocateIP failed on iteration %d: %v", i, err)
		}

		// Verify uniqueness
		if allocated[ipv4] {
			t.Errorf("Duplicate IP allocated: %s", ipv4)
		}
		allocated[ipv4] = true
	}

	// Verify all 50 IPs are unique
	if len(allocated) != 50 {
		t.Errorf("Expected 50 unique IPs, got %d", len(allocated))
	}
}

func TestReleaseIP(t *testing.T) {
	allocator := NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64")

	// Allocate an IP
	ipv4, ipv6, err := allocator.AllocateIP()
	if err != nil {
		t.Fatalf("AllocateIP failed: %v", err)
	}

	// Verify IPs are held
	if !allocator.heldIPv4[ipv4] {
		t.Error("IPv4 should be marked as held")
	}
	if !allocator.heldIPv6[ipv6] {
		t.Error("IPv6 should be marked as held")
	}

	// Release the IPs
	allocator.ReleaseIP(ipv4, ipv6)

	// Verify IPs are no longer held
	if allocator.heldIPv4[ipv4] {
		t.Error("IPv4 should not be marked as held after release")
	}
	if allocator.heldIPv6[ipv6] {
		t.Error("IPv6 should not be marked as held after release")
	}
}

func TestReleaseIP_AllowsReallocation(t *testing.T) {
	allocator := NewIPAllocator("10.0.0.1", "255.255.255.0", "")

	// Allocate all possible IPs in a small range
	// With random allocation, we might not fill completely, but we can test release/realloc
	allocated := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		ipv4, _, err := allocator.AllocateIP()
		if err != nil {
			t.Fatalf("AllocateIP failed: %v", err)
		}
		allocated = append(allocated, ipv4)
	}

	// Release first 5 IPs
	for i := 0; i < 5; i++ {
		allocator.ReleaseIP(allocated[i], "")
	}

	// Should be able to allocate 5 more IPs
	for i := 0; i < 5; i++ {
		_, _, err := allocator.AllocateIP()
		if err != nil {
			t.Errorf("Failed to reallocate after release: %v", err)
		}
	}
}

func TestParseIPv4Config(t *testing.T) {
	tests := []struct {
		name     string
		serverIP string
		netmask  string
		wantNil  bool
	}{
		{
			name:     "Valid /24 network",
			serverIP: "10.0.0.1",
			netmask:  "255.255.255.0",
			wantNil:  false,
		},
		{
			name:     "Valid /16 network",
			serverIP: "192.168.1.1",
			netmask:  "255.255.0.0",
			wantNil:  false,
		},
		{
			name:     "Invalid server IP",
			serverIP: "invalid",
			netmask:  "255.255.255.0",
			wantNil:  true,
		},
		{
			name:     "Invalid netmask",
			serverIP: "10.0.0.1",
			netmask:  "invalid",
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, mask := parseIPv4Config(tt.serverIP, tt.netmask)

			if tt.wantNil {
				if network != nil || mask != nil {
					t.Error("Expected nil result for invalid input")
				}
			} else {
				if network == nil || mask == nil {
					t.Error("Expected non-nil result for valid input")
				}
			}
		})
	}
}

func TestParseIPv6Config(t *testing.T) {
	tests := []struct {
		name       string
		serverIPv6 string
		wantNil    bool
		wantPrefix int
	}{
		{
			name:       "Valid /64 network",
			serverIPv6: "fd00::1/64",
			wantNil:    false,
			wantPrefix: 64,
		},
		{
			name:       "Valid /48 network",
			serverIPv6: "2001:db8::1/48",
			wantNil:    false,
			wantPrefix: 48,
		},
		{
			name:       "Invalid CIDR",
			serverIPv6: "invalid",
			wantNil:    true,
		},
		{
			name:       "IPv4 address (should fail)",
			serverIPv6: "10.0.0.1/24",
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, prefix := parseIPv6Config(tt.serverIPv6)

			if tt.wantNil {
				if network != nil {
					t.Error("Expected nil result for invalid input")
				}
			} else {
				if network == nil {
					t.Error("Expected non-nil result for valid input")
				}
				if prefix != tt.wantPrefix {
					t.Errorf("Expected prefix %d, got %d", tt.wantPrefix, prefix)
				}
			}
		})
	}
}

func TestAllocateIP_ConcurrentSafety(t *testing.T) {
	allocator := NewIPAllocator("10.0.0.1", "255.255.255.0", "")

	// Test concurrent allocations
	done := make(chan string, 10)
	for i := 0; i < 10; i++ {
		go func() {
			ipv4, _, err := allocator.AllocateIP()
			if err != nil {
				done <- ""
				return
			}
			done <- ipv4
		}()
	}

	// Collect results
	allocated := make(map[string]bool)
	for i := 0; i < 10; i++ {
		ipv4 := <-done
		if ipv4 != "" {
			if allocated[ipv4] {
				t.Errorf("Duplicate IP allocated in concurrent test: %s", ipv4)
			}
			allocated[ipv4] = true
		}
	}

	// Should have at least some successful allocations
	if len(allocated) == 0 {
		t.Error("No IPs were successfully allocated in concurrent test")
	}
}
