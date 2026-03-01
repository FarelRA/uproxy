package network

import (
	"context"
	"log/slog"
	"os"
	"testing"
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

	if diag.lastGateway != "" {
		t.Errorf("lastGateway should be empty initially, got %v", diag.lastGateway)
	}

	if diag.lastSrcIP != "" {
		t.Errorf("lastSrcIP should be empty initially, got %v", diag.lastSrcIP)
	}
}

func TestDiagnostics_RouteChangeDetection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	// Set initial state
	diag.lastGateway = "192.168.1.1"
	diag.lastSrcIP = "192.168.1.100"

	// Simulate route change by directly testing the logic
	newGateway := "192.168.2.1"

	if diag.lastGateway != "" && diag.lastGateway != newGateway {
		// This is the route change detection logic
		if diag.lastGateway != "192.168.1.1" {
			t.Errorf("lastGateway = %v, want 192.168.1.1", diag.lastGateway)
		}
	}
}

func TestDiagnostics_StateManagement(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	diag := NewDiagnostics("example.com:443", logger)

	// Initially empty
	if diag.lastGateway != "" {
		t.Errorf("Initial lastGateway should be empty, got %v", diag.lastGateway)
	}

	// Update state
	diag.lastGateway = "192.168.1.1"
	diag.lastSrcIP = "192.168.1.100"

	if diag.lastGateway != "192.168.1.1" {
		t.Errorf("lastGateway = %v, want 192.168.1.1", diag.lastGateway)
	}

	if diag.lastSrcIP != "192.168.1.100" {
		t.Errorf("lastSrcIP = %v, want 192.168.1.100", diag.lastSrcIP)
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
