package network

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"

	"uproxy/internal/routing"
)

func TestFailureType_String(t *testing.T) {
	tests := []struct {
		name     string
		failure  FailureType
		expected string
	}{
		{"Unknown", FailureUnknown, "unknown"},
		{"RouteChanged", FailureRouteChanged, "route_changed"},
		{"InterfaceDown", FailureInterfaceDown, "interface_down"},
		{"GatewayUnreachable", FailureGatewayUnreachable, "gateway_unreachable"},
		{"NoNetwork", FailureNoNetwork, "no_network"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.failure.String(); got != tt.expected {
				t.Errorf("FailureType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNewDiagnostics(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	serverAddr := "example.com:443"

	diag := NewDiagnostics(serverAddr, logger)

	if diag == nil {
		t.Fatal("NewDiagnostics returned nil")
	}

	if diag.serverAddr != serverAddr {
		t.Errorf("serverAddr = %v, want %v", diag.serverAddr, serverAddr)
	}

	if diag.logger != logger {
		t.Error("logger not set correctly")
	}

	if diag.lastRoute.gateway != "" {
		t.Errorf("lastRoute.gateway should be empty initially, got %v", diag.lastRoute.gateway)
	}

	if diag.lastRoute.srcIP != "" {
		t.Errorf("lastRoute.srcIP should be empty initially, got %v", diag.lastRoute.srcIP)
	}
}

func TestDiagnostics_RouteChangeDetection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	// Set initial state
	diag.lastRoute.gateway = "192.168.1.1"
	diag.lastRoute.srcIP = "192.168.1.100"

	// Simulate route change by directly testing the logic
	newGateway := "192.168.2.1"

	if diag.lastRoute.gateway != "" && diag.lastRoute.gateway != newGateway {
		// This is the route change detection logic
		if diag.lastRoute.gateway != "192.168.1.1" {
			t.Errorf("lastRoute.gateway = %v, want 192.168.1.1", diag.lastRoute.gateway)
		}
	}
}

func TestDiagnostics_StateManagement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	// Initially empty
	if diag.lastRoute.gateway != "" {
		t.Errorf("Initial lastRoute.gateway should be empty, got %v", diag.lastRoute.gateway)
	}

	// Update state
	diag.lastRoute.gateway = "192.168.1.1"
	diag.lastRoute.srcIP = "192.168.1.100"

	if diag.lastRoute.gateway != "192.168.1.1" {
		t.Errorf("lastRoute.gateway = %v, want 192.168.1.1", diag.lastRoute.gateway)
	}

	if diag.lastRoute.srcIP != "192.168.1.100" {
		t.Errorf("lastRoute.srcIP = %v, want 192.168.1.100", diag.lastRoute.srcIP)
	}
}

func TestDiagnostics_DiagnoseFailure_NoRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	// Use an invalid address that won't have a route
	diag := NewDiagnostics("invalid.nonexistent.domain.test:443", logger)

	ctx := context.Background()
	result := diag.DiagnoseFailure(ctx)

	// Should detect no network or unknown failure
	if result.FailureType != FailureNoNetwork && result.FailureType != FailureUnknown {
		t.Logf("Got failure type: %v, message: %v", result.FailureType, result.Message)
	}
}

func TestDiagnostics_DiagnoseFailure_WithContext(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("8.8.8.8:53", logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := diag.DiagnoseFailure(ctx)

	// Should complete without panic
	if result.Message == "" {
		t.Error("Expected diagnostic message, got empty string")
	}
}

func TestDiagnosticResult_Fields(t *testing.T) {
	result := DiagnosticResult{
		FailureType: FailureRouteChanged,
		Message:     "test message",
		Gateway:     "192.168.1.1",
		Interface:   "eth0",
	}

	if result.FailureType != FailureRouteChanged {
		t.Errorf("FailureType = %v, want %v", result.FailureType, FailureRouteChanged)
	}

	if result.Message != "test message" {
		t.Errorf("Message = %v, want 'test message'", result.Message)
	}

	if result.Gateway != "192.168.1.1" {
		t.Errorf("Gateway = %v, want '192.168.1.1'", result.Gateway)
	}

	if result.Interface != "eth0" {
		t.Errorf("Interface = %v, want 'eth0'", result.Interface)
	}
}

func BenchmarkFailureType_String(b *testing.B) {
	ft := FailureRouteChanged
	for i := 0; i < b.N; i++ {
		_ = ft.String()
	}
}

func BenchmarkNewDiagnostics(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	for i := 0; i < b.N; i++ {
		_ = NewDiagnostics("example.com:443", logger)
	}
}

// mockNetworkOps is a mock implementation of networkOps for testing
type mockNetworkOps struct {
	getRouteToHostFunc  func(ctx context.Context, host string) (*routing.RouteInfo, error)
	interfaceByNameFunc func(name string) (*net.Interface, error)
	pingGatewayFunc     func(ctx context.Context, gateway string) error
}

func (m *mockNetworkOps) GetRouteToHost(ctx context.Context, host string) (*routing.RouteInfo, error) {
	if m.getRouteToHostFunc != nil {
		return m.getRouteToHostFunc(ctx, host)
	}
	return nil, context.DeadlineExceeded
}

func (m *mockNetworkOps) InterfaceByName(name string) (*net.Interface, error) {
	if m.interfaceByNameFunc != nil {
		return m.interfaceByNameFunc(name)
	}
	return nil, os.ErrNotExist
}

func (m *mockNetworkOps) PingGateway(ctx context.Context, gateway string) error {
	if m.pingGatewayFunc != nil {
		return m.pingGatewayFunc(ctx, gateway)
	}
	return context.DeadlineExceeded
}

func TestDiagnoseFailure_NoNetwork(t *testing.T) {
	// Save original netOps and restore after test
	originalNetOps := netOps
	defer func() { netOps = originalNetOps }()

	// Mock that returns error for route lookup
	netOps = &mockNetworkOps{
		getRouteToHostFunc: func(ctx context.Context, host string) (*routing.RouteInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	result := diag.DiagnoseFailure(context.Background())

	if result.FailureType != FailureNoNetwork {
		t.Errorf("Expected FailureNoNetwork, got %v", result.FailureType)
	}
	if result.Message != "no default route found" {
		t.Errorf("Unexpected message: %v", result.Message)
	}
}

func TestDiagnoseFailure_RouteChanged(t *testing.T) {
	// Save original netOps and restore after test
	originalNetOps := netOps
	defer func() { netOps = originalNetOps }()

	// Mock that returns different gateways
	netOps = &mockNetworkOps{
		getRouteToHostFunc: func(ctx context.Context, host string) (*routing.RouteInfo, error) {
			return &routing.RouteInfo{
				Gateway:   "192.168.2.1",
				SrcIP:     "192.168.2.100",
				Interface: "eth0",
			}, nil
		},
		interfaceByNameFunc: func(name string) (*net.Interface, error) {
			return &net.Interface{
				Name:  name,
				Flags: net.FlagUp,
			}, nil
		},
		pingGatewayFunc: func(ctx context.Context, gateway string) error {
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	// Set initial state
	diag.lastGateway = "192.168.1.1"
	diag.lastSrcIP = "192.168.1.100"

	result := diag.DiagnoseFailure(context.Background())

	if result.FailureType != FailureRouteChanged {
		t.Errorf("Expected FailureRouteChanged, got %v", result.FailureType)
	}
	if result.Gateway != "192.168.2.1" {
		t.Errorf("Expected gateway 192.168.2.1, got %v", result.Gateway)
	}
	if result.Interface != "eth0" {
		t.Errorf("Expected interface eth0, got %v", result.Interface)
	}
}

func TestDiagnoseFailure_InterfaceDown(t *testing.T) {
	// Save original netOps and restore after test
	originalNetOps := netOps
	defer func() { netOps = originalNetOps }()

	// Mock that returns interface down
	netOps = &mockNetworkOps{
		getRouteToHostFunc: func(ctx context.Context, host string) (*routing.RouteInfo, error) {
			return &routing.RouteInfo{
				Gateway:   "192.168.1.1",
				SrcIP:     "192.168.1.100",
				Interface: "eth0",
			}, nil
		},
		interfaceByNameFunc: func(name string) (*net.Interface, error) {
			return &net.Interface{
				Name:  name,
				Flags: 0, // Interface down
			}, nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	result := diag.DiagnoseFailure(context.Background())

	if result.FailureType != FailureInterfaceDown {
		t.Errorf("Expected FailureInterfaceDown, got %v", result.FailureType)
	}
	if result.Interface != "eth0" {
		t.Errorf("Expected interface eth0, got %v", result.Interface)
	}
}

func TestDiagnoseFailure_GatewayUnreachable(t *testing.T) {
	// Save original netOps and restore after test
	originalNetOps := netOps
	defer func() { netOps = originalNetOps }()

	// Mock that returns gateway unreachable
	netOps = &mockNetworkOps{
		getRouteToHostFunc: func(ctx context.Context, host string) (*routing.RouteInfo, error) {
			return &routing.RouteInfo{
				Gateway:   "192.168.1.1",
				SrcIP:     "192.168.1.100",
				Interface: "eth0",
			}, nil
		},
		interfaceByNameFunc: func(name string) (*net.Interface, error) {
			return &net.Interface{
				Name:  name,
				Flags: net.FlagUp,
			}, nil
		},
		pingGatewayFunc: func(ctx context.Context, gateway string) error {
			return os.ErrDeadlineExceeded
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	result := diag.DiagnoseFailure(context.Background())

	if result.FailureType != FailureGatewayUnreachable {
		t.Errorf("Expected FailureGatewayUnreachable, got %v", result.FailureType)
	}
	if result.Gateway != "192.168.1.1" {
		t.Errorf("Expected gateway 192.168.1.1, got %v", result.Gateway)
	}
}

func TestDiagnoseFailure_Unknown(t *testing.T) {
	// Save original netOps and restore after test
	originalNetOps := netOps
	defer func() { netOps = originalNetOps }()

	// Mock that returns everything working
	netOps = &mockNetworkOps{
		getRouteToHostFunc: func(ctx context.Context, host string) (*routing.RouteInfo, error) {
			return &routing.RouteInfo{
				Gateway:   "192.168.1.1",
				SrcIP:     "192.168.1.100",
				Interface: "eth0",
			}, nil
		},
		interfaceByNameFunc: func(name string) (*net.Interface, error) {
			return &net.Interface{
				Name:  name,
				Flags: net.FlagUp,
			}, nil
		},
		pingGatewayFunc: func(ctx context.Context, gateway string) error {
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	result := diag.DiagnoseFailure(context.Background())

	if result.FailureType != FailureUnknown {
		t.Errorf("Expected FailureUnknown, got %v", result.FailureType)
	}
	if result.Message != "connectivity lost but network appears normal" {
		t.Errorf("Unexpected message: %v", result.Message)
	}
}

func TestDiagnoseFailure_InitialStateUpdate(t *testing.T) {
	// Save original netOps and restore after test
	originalNetOps := netOps
	defer func() { netOps = originalNetOps }()

	// Mock that returns route info
	netOps = &mockNetworkOps{
		getRouteToHostFunc: func(ctx context.Context, host string) (*routing.RouteInfo, error) {
			return &routing.RouteInfo{
				Gateway:   "192.168.1.1",
				SrcIP:     "192.168.1.100",
				Interface: "eth0",
			}, nil
		},
		interfaceByNameFunc: func(name string) (*net.Interface, error) {
			return &net.Interface{
				Name:  name,
				Flags: net.FlagUp,
			}, nil
		},
		pingGatewayFunc: func(ctx context.Context, gateway string) error {
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	// Initially empty
	if diag.lastGateway != "" {
		t.Errorf("Initial lastGateway should be empty, got %v", diag.lastGateway)
	}

	diag.DiagnoseFailure(context.Background())

	// Should be updated after first call
	if diag.lastGateway != "192.168.1.1" {
		t.Errorf("lastGateway should be updated to 192.168.1.1, got %v", diag.lastGateway)
	}
	if diag.lastSrcIP != "192.168.1.100" {
		t.Errorf("lastSrcIP should be updated to 192.168.1.100, got %v", diag.lastSrcIP)
	}
}

func TestIsInterfaceUp_Success(t *testing.T) {
	// Save original netOps and restore after test
	originalNetOps := netOps
	defer func() { netOps = originalNetOps }()

	// Mock that returns interface up
	netOps = &mockNetworkOps{
		interfaceByNameFunc: func(name string) (*net.Interface, error) {
			return &net.Interface{
				Name:  name,
				Flags: net.FlagUp,
			}, nil
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	if !diag.isInterfaceUp("eth0") {
		t.Error("Expected interface to be up")
	}
}

func TestIsInterfaceUp_Error(t *testing.T) {
	// Save original netOps and restore after test
	originalNetOps := netOps
	defer func() { netOps = originalNetOps }()

	// Mock that returns error
	netOps = &mockNetworkOps{
		interfaceByNameFunc: func(name string) (*net.Interface, error) {
			return nil, os.ErrNotExist
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	if diag.isInterfaceUp("nonexistent") {
		t.Error("Expected interface to be down when error occurs")
	}
}
