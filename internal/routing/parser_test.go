package routing

import (
	"testing"
)

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
			name:        "complete default route",
			output:      "default via 10.0.0.1 dev wlan0 src 10.0.0.118 metric 600",
			wantGateway: "10.0.0.1",
			wantIface:   "wlan0",
			wantSrcIP:   "10.0.0.118",
			wantErr:     false,
		},
		{
			name:        "route without src",
			output:      "default via 192.168.1.1 dev eth0",
			wantGateway: "192.168.1.1",
			wantIface:   "eth0",
			wantSrcIP:   "",
			wantErr:     false,
		},
		{
			name:        "route with metric",
			output:      "default via 172.16.0.1 dev enp0s3 proto dhcp metric 100",
			wantGateway: "172.16.0.1",
			wantIface:   "enp0s3",
			wantSrcIP:   "",
			wantErr:     false,
		},
		{
			name:        "ipv6 route",
			output:      "default via fe80::1 dev eth0 proto ra metric 1024",
			wantGateway: "fe80::1",
			wantIface:   "eth0",
			wantSrcIP:   "",
			wantErr:     false,
		},
		{
			name:        "route get output",
			output:      "8.8.8.8 via 192.168.1.1 dev wlan0 src 192.168.1.100 uid 1000",
			wantGateway: "192.168.1.1",
			wantIface:   "wlan0",
			wantSrcIP:   "192.168.1.100",
			wantErr:     false,
		},
		{
			name:    "missing gateway",
			output:  "default dev eth0",
			wantErr: true,
		},
		{
			name:    "missing interface",
			output:  "default via 10.0.0.1",
			wantErr: true,
		},
		{
			name:    "empty output",
			output:  "",
			wantErr: true,
		},
		{
			name:    "malformed output",
			output:  "some random text",
			wantErr: true,
		},
		{
			name:        "extra whitespace",
			output:      "default  via   10.0.0.1   dev   eth0",
			wantGateway: "10.0.0.1",
			wantIface:   "eth0",
			wantSrcIP:   "",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseIPRouteOutput(tt.output)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseIPRouteOutput() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseIPRouteOutput() unexpected error: %v", err)
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
		_, err := ParseIPRouteOutput("default dev eth0 via")
		if err == nil {
			t.Error("expected error for incomplete via clause")
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
}

func TestRouteInfo_Structure(t *testing.T) {
	// Test that RouteInfo can be created and fields are accessible
	info := &RouteInfo{
		Gateway:   "192.168.1.1",
		Interface: "eth0",
		SrcIP:     "192.168.1.100",
	}

	if info.Gateway != "192.168.1.1" {
		t.Errorf("Gateway field not accessible")
	}
	if info.Interface != "eth0" {
		t.Errorf("Interface field not accessible")
	}
	if info.SrcIP != "192.168.1.100" {
		t.Errorf("SrcIP field not accessible")
	}
}
