package network

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"time"

	"uproxy/internal/routing"
)

// FailureType represents the type of network failure detected
type FailureType int

const (
	FailureUnknown FailureType = iota
	FailureRouteChanged
	FailureInterfaceDown
	FailureGatewayUnreachable
	FailureNoNetwork
)

func (f FailureType) String() string {
	switch f {
	case FailureRouteChanged:
		return "route_changed"
	case FailureInterfaceDown:
		return "interface_down"
	case FailureGatewayUnreachable:
		return "gateway_unreachable"
	case FailureNoNetwork:
		return "no_network"
	default:
		return "unknown"
	}
}

// DiagnosticResult contains the result of network diagnostics
type DiagnosticResult struct {
	FailureType FailureType
	Message     string
	Gateway     string
	Interface   string
}

// Diagnostics provides network failure diagnosis capabilities
type Diagnostics struct {
	serverAddr  string
	lastGateway string
	lastSrcIP   string
	logger      *slog.Logger
}

// NewDiagnostics creates a new network diagnostics instance
func NewDiagnostics(serverAddr string, logger *slog.Logger) *Diagnostics {
	return &Diagnostics{
		serverAddr: serverAddr,
		logger:     logger,
	}
}

// DiagnoseFailure analyzes the network to determine the cause of connectivity failure
func (d *Diagnostics) DiagnoseFailure(ctx context.Context) DiagnosticResult {
	// Check if default route exists
	gateway, srcIP, iface, err := d.getDefaultRoute(ctx)
	if err != nil {
		d.logger.Warn("Failed to get default route", "error", err)
		return DiagnosticResult{
			FailureType: FailureNoNetwork,
			Message:     "no default route found",
		}
	}

	// Check if route changed
	if d.lastGateway != "" && d.lastGateway != gateway {
		d.logger.Info("Route change detected",
			"old_gateway", d.lastGateway,
			"new_gateway", gateway,
			"old_src_ip", d.lastSrcIP,
			"new_src_ip", srcIP)

		d.lastGateway = gateway
		d.lastSrcIP = srcIP

		return DiagnosticResult{
			FailureType: FailureRouteChanged,
			Message:     fmt.Sprintf("gateway changed from %s to %s", d.lastGateway, gateway),
			Gateway:     gateway,
			Interface:   iface,
		}
	}

	// Update last known good state
	if d.lastGateway == "" {
		d.lastGateway = gateway
		d.lastSrcIP = srcIP
	}

	// Check if interface is up
	if !d.isInterfaceUp(iface) {
		return DiagnosticResult{
			FailureType: FailureInterfaceDown,
			Message:     fmt.Sprintf("interface %s is down", iface),
			Interface:   iface,
		}
	}

	// Check if gateway is reachable
	if !d.isGatewayReachable(ctx, gateway) {
		return DiagnosticResult{
			FailureType: FailureGatewayUnreachable,
			Message:     fmt.Sprintf("gateway %s is unreachable", gateway),
			Gateway:     gateway,
		}
	}

	return DiagnosticResult{
		FailureType: FailureUnknown,
		Message:     "connectivity lost but network appears normal",
	}
}

// getDefaultRoute retrieves the default gateway, source IP, and interface
func (d *Diagnostics) getDefaultRoute(ctx context.Context) (gateway, srcIP, iface string, err error) {
	// Try to get route to server address
	host := ExtractHost(d.serverAddr)

	info, err := routing.GetRouteToHost(ctx, host)
	if err != nil {
		return "", "", "", err
	}

	return info.Gateway, info.SrcIP, info.Interface, nil
}

// isInterfaceUp checks if a network interface is up
func (d *Diagnostics) isInterfaceUp(ifaceName string) bool {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return false
	}
	return iface.Flags&net.FlagUp != 0
}

// isGatewayReachable checks if the gateway responds to ping
func (d *Diagnostics) isGatewayReachable(ctx context.Context, gateway string) bool {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", gateway)
	err := cmd.Run()
	return err == nil
}
