// Package network provides network diagnostics and connectivity monitoring utilities.
// It includes functionality for diagnosing connection failures, detecting network changes,
// and resolving IP addresses.
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

// Ping command constants
const (
	pingCountArg      = "-c"
	pingCountValue    = "1"
	pingTimeoutArg    = "-W"
	pingTimeoutValue  = "1"
	pingTimeoutSecond = 1 * time.Second
)

// networkOps defines operations for network diagnostics (for testing)
type networkOps interface {
	GetRouteToHost(ctx context.Context, host string) (*routing.RouteInfo, error)
	InterfaceByName(name string) (*net.Interface, error)
	PingGateway(ctx context.Context, gateway string) error
}

// defaultNetworkOps implements networkOps using real network operations
type defaultNetworkOps struct{}

func (d *defaultNetworkOps) GetRouteToHost(ctx context.Context, host string) (*routing.RouteInfo, error) {
	return routing.GetRouteToHost(ctx, host)
}

func (d *defaultNetworkOps) InterfaceByName(name string) (*net.Interface, error) {
	return net.InterfaceByName(name)
}

func (d *defaultNetworkOps) PingGateway(ctx context.Context, gateway string) error {
	ctx, cancel := context.WithTimeout(ctx, pingTimeoutSecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", pingCountArg, pingCountValue, pingTimeoutArg, pingTimeoutValue, gateway)
	return cmd.Run()
}

var netOps networkOps = &defaultNetworkOps{}

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

// routeState holds the previous route state for change detection
type routeState struct {
	gateway string
	srcIP   string
}

// Diagnostics provides network failure diagnosis capabilities
type Diagnostics struct {
	serverAddr string
	lastRoute  routeState
	logger     *slog.Logger
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
	if changed, result := d.checkRouteChange(gateway, srcIP, iface); changed {
		return result
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

// checkRouteChange detects if the route has changed and updates state accordingly
func (d *Diagnostics) checkRouteChange(gateway, srcIP, iface string) (bool, DiagnosticResult) {
	// First connection - initialize state
	if d.lastRoute.gateway == "" {
		d.lastRoute = routeState{gateway: gateway, srcIP: srcIP}
		return false, DiagnosticResult{}
	}

	// Check if route changed
	if d.lastRoute.gateway != gateway || d.lastRoute.srcIP != srcIP {
		msg := fmt.Sprintf("route changed: gateway %s->%s, src %s->%s",
			d.lastRoute.gateway, gateway, d.lastRoute.srcIP, srcIP)
		d.lastRoute = routeState{gateway: gateway, srcIP: srcIP}
		return true, DiagnosticResult{
			FailureType: FailureRouteChanged,
			Message:     msg,
			Gateway:     gateway,
			Interface:   iface,
		}
	}

	return false, DiagnosticResult{}
}

// getDefaultRoute retrieves the default gateway, source IP, and interface
func (d *Diagnostics) getDefaultRoute(ctx context.Context) (gateway, srcIP, iface string, err error) {
	// Try to get route to server address
	host := ExtractHost(d.serverAddr)

	info, err := netOps.GetRouteToHost(ctx, host)
	if err != nil {
		return "", "", "", err
	}

	return info.Gateway, info.SrcIP, info.Interface, nil
}

// isInterfaceUp checks if a network interface is up
func (d *Diagnostics) isInterfaceUp(ifaceName string) bool {
	iface, err := netOps.InterfaceByName(ifaceName)
	if err != nil {
		return false
	}
	return iface.Flags&net.FlagUp != 0
}

// isGatewayReachable checks if the gateway responds to ping
func (d *Diagnostics) isGatewayReachable(ctx context.Context, gateway string) bool {
	err := netOps.PingGateway(ctx, gateway)
	return err == nil
}
