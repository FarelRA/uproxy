package routing

import (
	"context"
	"errors"
	"testing"
)

// mockExecutor is a mock implementation of commandExecutor for testing
type mockExecutor struct {
	combinedOutputFunc func(name string, args ...string) ([]byte, error)
	outputFunc         func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (m *mockExecutor) CombinedOutput(name string, args ...string) ([]byte, error) {
	if m.combinedOutputFunc != nil {
		return m.combinedOutputFunc(name, args...)
	}
	return nil, errors.New("not implemented")
}

func (m *mockExecutor) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if m.outputFunc != nil {
		return m.outputFunc(ctx, name, args...)
	}
	return nil, errors.New("not implemented")
}

func TestParseIPRouteOutput(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantGateway string
		wantIface   string
		wantSrcIP   string
		wantErr     bool
	}{
		{
			name:        "standard route",
			output:      "default via 192.168.1.1 dev eth0 src 192.168.1.100",
			wantGateway: "192.168.1.1",
			wantIface:   "eth0",
			wantSrcIP:   "192.168.1.100",
			wantErr:     false,
		},
		{
			name:        "route without src",
			output:      "default via 10.0.0.1 dev wlan0",
			wantGateway: "10.0.0.1",
			wantIface:   "wlan0",
			wantSrcIP:   "",
			wantErr:     false,
		},
		{
			name:        "route with extra fields",
			output:      "default via 172.16.0.1 dev enp0s3 proto dhcp metric 100 src 172.16.0.50",
			wantGateway: "172.16.0.1",
			wantIface:   "enp0s3",
			wantSrcIP:   "172.16.0.50",
			wantErr:     false,
		},
		{
			name:    "empty output",
			output:  "",
			wantErr: true,
		},
		{
			name:        "no default keyword",
			output:      "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100",
			wantGateway: "",
			wantIface:   "eth0",
			wantSrcIP:   "192.168.1.100",
			wantErr:     false, // Parser doesn't validate "default" keyword, just parses route info
		},
		{
			name:        "missing gateway",
			output:      "default dev eth0",
			wantGateway: "",
			wantIface:   "eth0",
			wantSrcIP:   "",
			wantErr:     false, // Gateway is optional for local routes
		},
		{
			name:    "missing interface",
			output:  "default via 192.168.1.1",
			wantErr: true,
		},
		{
			name:    "dev without value",
			output:  "default via 192.168.1.1 dev",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseIPRouteOutput(tt.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPRouteOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if info.Gateway != tt.wantGateway {
				t.Errorf("Gateway = %q, want %q", info.Gateway, tt.wantGateway)
			}
			if info.Interface != tt.wantIface {
				t.Errorf("Interface = %q, want %q", info.Interface, tt.wantIface)
			}
			if info.SrcIP != tt.wantSrcIP {
				t.Errorf("SrcIP = %q, want %q", info.SrcIP, tt.wantSrcIP)
			}
		})
	}
}

func TestParseIPRouteOutput_EdgeCases(t *testing.T) {
	t.Run("via at end", func(t *testing.T) {
		// via at end means no gateway value, but interface is present
		info, err := ParseIPRouteOutput("default dev eth0 via")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if info.Gateway != "" {
			t.Errorf("Gateway should be empty, got %q", info.Gateway)
		}
		if info.Interface != "eth0" {
			t.Errorf("Interface = %q, want eth0", info.Interface)
		}
	})

	t.Run("dev at end", func(t *testing.T) {
		_, err := ParseIPRouteOutput("default via 10.0.0.1 dev")
		if err == nil {
			t.Error("expected error for incomplete dev clause")
		}
	})

	t.Run("src at end", func(t *testing.T) {
		// src is optional, so missing value should still parse if gateway and dev are present
		info, err := ParseIPRouteOutput("default via 10.0.0.1 dev eth0 src")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if info.SrcIP != "" {
			t.Errorf("SrcIP should be empty, got %q", info.SrcIP)
		}
	})

	t.Run("multiple via keywords", func(t *testing.T) {
		// Should use the first occurrence
		info, err := ParseIPRouteOutput("default via 10.0.0.1 dev eth0 via 10.0.0.2")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if info.Gateway != "10.0.0.1" {
			t.Errorf("Gateway = %q, want 10.0.0.1", info.Gateway)
		}
	})

	t.Run("multiple dev keywords", func(t *testing.T) {
		// Should use the first occurrence
		info, err := ParseIPRouteOutput("default via 10.0.0.1 dev eth0 dev wlan0")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if info.Interface != "eth0" {
			t.Errorf("Interface = %q, want eth0", info.Interface)
		}
	})

	t.Run("whitespace variations", func(t *testing.T) {
		info, err := ParseIPRouteOutput("  default   via   10.0.0.1   dev   eth0  ")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if info.Gateway != "10.0.0.1" || info.Interface != "eth0" {
			t.Errorf("Failed to parse with extra whitespace")
		}
	})
}

func TestGetDefaultRoute(t *testing.T) {
	// Test that GetDefaultRoute executes without panic
	// Actual behavior depends on system configuration
	info, err := GetDefaultRoute()

	if err != nil {
		// It's okay if the command fails on systems without proper routing
		t.Logf("GetDefaultRoute failed (expected on some systems): %v", err)
		return
	}

	// If successful, validate the structure
	if info == nil {
		t.Error("GetDefaultRoute returned nil info without error")
		return
	}

	// On systems with routing, we should have at least a gateway or interface
	if info.Gateway == "" && info.Interface == "" {
		t.Error("GetDefaultRoute returned empty gateway and interface")
	}

	t.Logf("Default route: gateway=%s, interface=%s, src=%s",
		info.Gateway, info.Interface, info.SrcIP)
}

func TestGetDefaultIPv6Route(t *testing.T) {
	// Test that GetDefaultIPv6Route executes without panic
	// IPv6 might not be configured, which is okay
	info, err := GetDefaultIPv6Route()

	if err != nil {
		t.Errorf("GetDefaultIPv6Route should not return error: %v", err)
		return
	}

	if info == nil {
		t.Error("GetDefaultIPv6Route returned nil info")
		return
	}

	// IPv6 might not be configured, so empty info is acceptable
	t.Logf("Default IPv6 route: gateway=%s, interface=%s, src=%s",
		info.Gateway, info.Interface, info.SrcIP)
}

func TestGetRouteToHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{
			name:    "valid host - localhost",
			host:    "127.0.0.1",
			wantErr: false,
		},
		{
			name:    "valid host - google dns",
			host:    "8.8.8.8",
			wantErr: false,
		},
		{
			name:    "invalid host",
			host:    "invalid-host-that-does-not-exist-12345",
			wantErr: true,
		},
		{
			name:    "empty host",
			host:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			info, err := GetRouteToHost(ctx, tt.host)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetRouteToHost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if info == nil {
					t.Error("GetRouteToHost returned nil info without error")
					return
				}
				t.Logf("Route to %s: gateway=%s, interface=%s, src=%s",
					tt.host, info.Gateway, info.Interface, info.SrcIP)
			}
		})
	}
}

func TestGetRouteToHost_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := GetRouteToHost(ctx, "8.8.8.8")
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestParseIPRouteOutput_KeywordValidation(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantErr bool
	}{
		{
			name:    "via without value (keyword follows)",
			output:  "default via dev eth0",
			wantErr: false, // Gateway filtered out, but interface present
		},
		{
			name:    "dev without value (keyword follows)",
			output:  "default via 10.0.0.1 dev via",
			wantErr: true, // Interface filtered out as keyword, leaving no interface
		},
		{
			name:    "gateway is keyword",
			output:  "default via proto dev eth0",
			wantErr: false, // Gateway filtered out, but interface present
		},
		{
			name:    "no interface at all",
			output:  "default via 10.0.0.1",
			wantErr: true, // Interface is required
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseIPRouteOutput(tt.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPRouteOutput() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetDefaultRoute_CommandFailure(t *testing.T) {
	// Save original executor and restore after test
	originalExecutor := executor
	defer func() { executor = originalExecutor }()

	// Mock executor that returns an error
	executor = &mockExecutor{
		combinedOutputFunc: func(name string, args ...string) ([]byte, error) {
			return nil, errors.New("command failed")
		},
	}

	_, err := GetDefaultRoute()
	if err == nil {
		t.Error("expected error when command fails")
	}
}

func TestGetDefaultRoute_ParseFailure(t *testing.T) {
	// Save original executor and restore after test
	originalExecutor := executor
	defer func() { executor = originalExecutor }()

	// Mock executor that returns unparseable output
	executor = &mockExecutor{
		combinedOutputFunc: func(name string, args ...string) ([]byte, error) {
			return []byte("invalid output without interface"), nil
		},
	}

	_, err := GetDefaultRoute()
	if err == nil {
		t.Error("expected error when parsing fails")
	}
}

func TestGetDefaultRoute_MissingGateway(t *testing.T) {
	// Save original executor and restore after test
	originalExecutor := executor
	defer func() { executor = originalExecutor }()

	// Mock executor that returns output without gateway
	executor = &mockExecutor{
		combinedOutputFunc: func(name string, args ...string) ([]byte, error) {
			return []byte("default dev eth0"), nil
		},
	}

	info, err := GetDefaultRoute()
	if err != nil {
		t.Errorf("expected no error when gateway is missing but interface exists, got: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil route info")
	}
	if info.Interface != "eth0" {
		t.Errorf("expected interface eth0, got %q", info.Interface)
	}
	if info.Gateway != "" {
		t.Errorf("expected empty gateway, got %q", info.Gateway)
	}
}

func TestGetDefaultIPv6Route_ParseFailure(t *testing.T) {
	// Save original executor and restore after test
	originalExecutor := executor
	defer func() { executor = originalExecutor }()

	// Mock executor that returns unparseable output
	executor = &mockExecutor{
		combinedOutputFunc: func(name string, args ...string) ([]byte, error) {
			return []byte("invalid ipv6 output"), nil
		},
	}

	info, err := GetDefaultIPv6Route()
	if err != nil {
		t.Errorf("GetDefaultIPv6Route should not return error on parse failure: %v", err)
	}
	if info == nil {
		t.Error("GetDefaultIPv6Route should return empty RouteInfo, not nil")
	}
	if info.Gateway != "" || info.Interface != "" || info.SrcIP != "" {
		t.Error("GetDefaultIPv6Route should return empty RouteInfo on parse failure")
	}
}

func TestGetDefaultIPv6Route_CommandFailure(t *testing.T) {
	// Save original executor and restore after test
	originalExecutor := executor
	defer func() { executor = originalExecutor }()

	// Mock executor that returns an error
	executor = &mockExecutor{
		combinedOutputFunc: func(name string, args ...string) ([]byte, error) {
			return nil, errors.New("ipv6 command failed")
		},
	}

	info, err := GetDefaultIPv6Route()
	if err != nil {
		t.Errorf("GetDefaultIPv6Route should not return error on command failure: %v", err)
	}
	if info == nil {
		t.Error("GetDefaultIPv6Route should return empty RouteInfo, not nil")
	}
	if info.Gateway != "" || info.Interface != "" || info.SrcIP != "" {
		t.Error("GetDefaultIPv6Route should return empty RouteInfo on command failure")
	}
}
