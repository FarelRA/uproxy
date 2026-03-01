package tun

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// RouteManager handles route setup and cleanup for TUN interfaces
type RouteManager struct {
	serverAddr string
	tunDevice  string
	routeInfo  *RouteInfo
	logger     *slog.Logger
}

// NewRouteManager creates a new route manager
func NewRouteManager(serverAddr, tunDevice string, logger *slog.Logger) *RouteManager {
	return &RouteManager{
		serverAddr: serverAddr,
		tunDevice:  tunDevice,
		logger:     logger,
	}
}

// SetupRoutes configures routes for the TUN interface
func (rm *RouteManager) SetupRoutes(ctx context.Context) error {
	const (
		maxRetries = 150
		retryDelay = 100 * time.Millisecond
	)

	// Wait for TUN device to be ready
	if err := rm.waitForTunDevice(ctx); err != nil {
		return fmt.Errorf("TUN device not ready: %w", err)
	}

	// Retry route setup
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		info, err := SetupClientRoutes(rm.serverAddr, rm.tunDevice)
		if err == nil {
			rm.routeInfo = info
			rm.logger.Info("Routes configured successfully",
				"tun_device", rm.tunDevice,
				"server_ipv4", info.ServerIPv4,
				"server_ipv6", info.ServerIPv6)
			return nil
		}

		lastErr = err
		if i == maxRetries-1 {
			return fmt.Errorf("failed to setup routes after %d attempts: %w", maxRetries, lastErr)
		}

		time.Sleep(retryDelay)
	}

	return lastErr
}

// CleanupRoutes removes routes for the TUN interface
func (rm *RouteManager) CleanupRoutes() {
	if rm.routeInfo != nil {
		CleanupClientRoutes(rm.routeInfo)
		rm.routeInfo = nil
	}
}

// ResetRoutes cleans up and re-establishes routes (useful after route changes)
func (rm *RouteManager) ResetRoutes(ctx context.Context) error {
	rm.logger.Info("Resetting routes due to network change", "tun_device", rm.tunDevice)

	// Cleanup old routes
	rm.CleanupRoutes()

	// Setup new routes
	return rm.SetupRoutes(ctx)
}

// GetRouteInfo returns the current route information
func (rm *RouteManager) GetRouteInfo() *RouteInfo {
	return rm.routeInfo
}

// waitForTunDevice waits for the TUN device to become available
func (rm *RouteManager) waitForTunDevice(ctx context.Context) error {
	timeout := 3 * time.Second
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if isTunDeviceUp(rm.tunDevice) {
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("TUN device %s did not become ready within %v", rm.tunDevice, timeout)
}

// isTunDeviceUp checks if a TUN device is up
func isTunDeviceUp(name string) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	return iface.Flags&net.FlagUp != 0
}
