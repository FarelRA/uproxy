package tun

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

const (
	maxRetries = 150
	retryDelay = 100 * time.Millisecond
)

// RouteMonitor monitors network changes and maintains routes
type RouteMonitor struct {
	serverAddr string
	tunDevice  string
	routeInfo  *RouteInfo
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewRouteMonitor creates a new route monitor
func NewRouteMonitor(serverAddr, tunDevice string) *RouteMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &RouteMonitor{
		serverAddr: serverAddr,
		tunDevice:  tunDevice,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start sets up routes with retry and begins monitoring
func (rm *RouteMonitor) Start() error {
	slog.Info("Starting route monitor", "tun_device", rm.tunDevice)

	// Wait for TUN device to be ready
	if err := rm.waitForTunDevice(); err != nil {
		return fmt.Errorf("TUN device not ready: %w", err)
	}

	// Setup routes with retry
	if err := rm.setupRoutesWithRetry(); err != nil {
		return fmt.Errorf("failed to setup routes after retries: %w", err)
	}

	// Start monitoring network changes
	go rm.monitorNetworkChanges()

	return nil
}

// Stop stops monitoring and cleans up routes
func (rm *RouteMonitor) Stop() {
	slog.Info("Stopping route monitor")
	rm.cancel()

	if rm.routeInfo != nil {
		slog.Info("Cleaning up routes...")
		CleanupClientRoutes(rm.routeInfo)
	}
}

// waitForTunDevice waits for the TUN device to be available
func (rm *RouteMonitor) waitForTunDevice() error {
	slog.Info("Waiting for TUN device", "device", rm.tunDevice)

	for i := 0; i < 30; i++ {
		// Check if device exists and is up
		cmd := exec.Command("ip", "link", "show", rm.tunDevice)
		output, err := cmd.CombinedOutput()
		if err == nil && strings.Contains(string(output), "UP") {
			slog.Info("TUN device ready", "device", rm.tunDevice)
			return nil
		}

		select {
		case <-rm.ctx.Done():
			return rm.ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	return fmt.Errorf("timeout waiting for TUN device")
}

// setupRoutesWithRetry attempts to setup routes with retry logic
func (rm *RouteMonitor) setupRoutesWithRetry() error {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Get current default gateway
		gw, iface, srcIP, err := GetDefaultGateway()
		if err != nil {
			if attempt == 1 {
				slog.Warn("Route setup failed", "error", err)
				slog.Info("Routes not configured, entering retry phase...")
			}
			lastErr = err
			slog.Warn("Retry failed", "error", err, "attempt", attempt, "max", maxRetries)

			select {
			case <-rm.ctx.Done():
				return rm.ctx.Err()
			case <-time.After(retryDelay):
				continue
			}
		}

		// Log current default route
		ipv6gw, ipv6iface, ipv6src, _ := GetDefaultIPv6Gateway()
		if ipv6gw != "" {
			slog.Info("Default routes detected",
				"ipv4_iface", iface,
				"ipv4_src", srcIP,
				"ipv4_gw", gw,
				"ipv6_iface", ipv6iface,
				"ipv6_src", ipv6src,
				"ipv6_gw", ipv6gw)
		} else {
			slog.Info("Default route detected",
				"ipv4_iface", iface,
				"ipv4_src", srcIP,
				"ipv4_gw", gw)
		}

		// Attempt to setup routes
		info, err := SetupClientRoutes(rm.serverAddr, rm.tunDevice)
		if err != nil {
			if attempt == 1 {
				slog.Warn("Route setup failed", "error", err)
				slog.Info("Routes not configured, entering retry phase...")
			}
			lastErr = err
			slog.Warn("Retry failed", "error", err, "attempt", attempt, "max", maxRetries)

			select {
			case <-rm.ctx.Done():
				return rm.ctx.Err()
			case <-time.After(retryDelay):
				continue
			}
		}

		rm.routeInfo = info

		if attempt > 1 {
			slog.Info("Routes configured successfully after retry")
		}

		rm.logRoutesConfigured()
		return nil
	}

	return fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}

// startIPMonitor starts the ip monitor process and returns a channel for network changes
func (rm *RouteMonitor) startIPMonitor() (chan bool, error) {
	cmd := exec.CommandContext(rm.ctx, "ip", "monitor", "route", "address")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create ip monitor pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start ip monitor: %w", err)
	}

	changeChan := make(chan bool, 10)
	go rm.scanIPMonitorOutput(stdout, changeChan)
	go cmd.Wait()

	return changeChan, nil
}

// scanIPMonitorOutput scans the ip monitor output and signals changes
func (rm *RouteMonitor) scanIPMonitorOutput(stdout io.ReadCloser, changeChan chan<- bool) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		// Detect relevant changes (default route or address changes)
		if strings.Contains(line, "default") || strings.Contains(line, "Deleted") {
			select {
			case changeChan <- true:
			default:
				// Channel full, skip
			}
		}
	}
}

// monitorNetworkChanges watches for network changes and reconfigures routes
func (rm *RouteMonitor) monitorNetworkChanges() {
	slog.Info("Monitoring network changes...")

	// Track last known gateway to detect changes
	lastGW := rm.routeInfo.OriginalGW
	lastSrcIP := rm.routeInfo.OriginalSrcIP
	lastIPv6GW := rm.routeInfo.OriginalIPv6GW
	lastIPv6SrcIP := rm.routeInfo.OriginalIPv6SrcIP

	changeChan, err := rm.startIPMonitor()
	if err != nil {
		slog.Error("Failed to start IP monitor", "error", err)
		return
	}

	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-changeChan:
			// Network change detected, debounce and check
			time.Sleep(100 * time.Millisecond)
			rm.checkAndUpdateRoutes(&lastGW, &lastSrcIP, &lastIPv6GW, &lastIPv6SrcIP)
		}
	}
}

// checkAndUpdateRoutes checks if routes need updating and reconfigures if needed
func (rm *RouteMonitor) checkAndUpdateRoutes(lastGW, lastSrcIP, lastIPv6GW, lastIPv6SrcIP *string) {
	gw, iface, srcIP, err := GetDefaultGateway()
	if err != nil {
		// Default route might be temporarily missing
		return
	}

	ipv6gw, ipv6iface, ipv6src, _ := GetDefaultIPv6Gateway()

	// Check if anything changed
	gwChanged := gw != *lastGW
	srcChanged := srcIP != *lastSrcIP
	ipv6gwChanged := ipv6gw != *lastIPv6GW
	ipv6srcChanged := ipv6src != *lastIPv6SrcIP

	if !gwChanged && !srcChanged && !ipv6gwChanged && !ipv6srcChanged {
		return
	}

	// Log current state
	if ipv6gw != "" {
		slog.Info("Default routes detected",
			"ipv4_iface", iface,
			"ipv4_src", srcIP,
			"ipv4_gw", gw,
			"ipv6_iface", ipv6iface,
			"ipv6_src", ipv6src,
			"ipv6_gw", ipv6gw)
	} else {
		slog.Info("Default route detected",
			"ipv4_iface", iface,
			"ipv4_src", srcIP,
			"ipv4_gw", gw)
	}

	// Cleanup old routes
	if rm.routeInfo != nil {
		CleanupClientRoutes(rm.routeInfo)
	}

	// Setup new routes
	info, err := SetupClientRoutes(rm.serverAddr, rm.tunDevice)
	if err != nil {
		slog.Error("Failed to reconfigure routes", "error", err)
		// Try again with retry
		go func() {
			time.Sleep(500 * time.Millisecond)
			if err := rm.setupRoutesWithRetry(); err != nil {
				slog.Error("Failed to setup routes after network change", "error", err)
			}
		}()
		return
	}

	rm.routeInfo = info
	*lastGW = gw
	*lastSrcIP = srcIP
	*lastIPv6GW = ipv6gw
	*lastIPv6SrcIP = ipv6src

	rm.logRoutesConfigured()
	slog.Info("WAN route changed, routes updated")
}

// logRoutesConfigured logs the current route configuration
func (rm *RouteMonitor) logRoutesConfigured() {
	if rm.routeInfo == nil {
		return
	}

	if rm.routeInfo.OriginalIPv6GW != "" {
		slog.Info("Routes configured",
			"ipv4_iface", rm.routeInfo.OriginalIface,
			"ipv4_src", rm.routeInfo.OriginalSrcIP,
			"ipv4_gw", rm.routeInfo.OriginalGW,
			"ipv6_iface", rm.routeInfo.OriginalIPv6Iface,
			"ipv6_src", rm.routeInfo.OriginalIPv6SrcIP,
			"ipv6_gw", rm.routeInfo.OriginalIPv6GW,
			"tunnel", fmt.Sprintf("IPv4+IPv6 via %s", rm.tunDevice))
	} else {
		slog.Info("Routes configured",
			"ipv4_iface", rm.routeInfo.OriginalIface,
			"ipv4_src", rm.routeInfo.OriginalSrcIP,
			"ipv4_gw", rm.routeInfo.OriginalGW,
			"tunnel", fmt.Sprintf("IPv4+IPv6 via %s", rm.tunDevice))
	}
}
