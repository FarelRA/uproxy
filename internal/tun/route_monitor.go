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

// monitorState tracks the last known network state for change detection
type monitorState struct {
	lastGW        string
	lastSrcIP     string
	lastIPv6GW    string
	lastIPv6SrcIP string
}

// RouteMonitor monitors network changes and maintains routes
type RouteMonitor struct {
	routeManager *RouteManager
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewRouteMonitor creates a new route monitor
func NewRouteMonitor(serverAddr, tunDevice string) *RouteMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &RouteMonitor{
		routeManager: NewRouteManager(serverAddr, tunDevice, slog.Default()),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start sets up routes with retry and begins monitoring
func (rm *RouteMonitor) Start() error {
	slog.Info("Starting route monitor")

	// Setup routes using RouteManager (handles retry logic internally)
	if err := rm.routeManager.SetupRoutes(rm.ctx); err != nil {
		return fmt.Errorf("failed to setup routes: %w", err)
	}

	// Start monitoring network changes
	go rm.monitorNetworkChanges()

	return nil
}

// Stop stops monitoring and cleans up routes
func (rm *RouteMonitor) Stop() {
	slog.Info("Stopping route monitor")
	rm.cancel()
	rm.routeManager.CleanupRoutes()
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

	routeInfo := rm.routeManager.GetRouteInfo()
	if routeInfo == nil {
		slog.Error("No route info available for monitoring")
		return
	}

	// Track last known gateway to detect changes
	state := &monitorState{
		lastGW:        routeInfo.OriginalGW,
		lastSrcIP:     routeInfo.OriginalSrcIP,
		lastIPv6GW:    routeInfo.OriginalIPv6GW,
		lastIPv6SrcIP: routeInfo.OriginalIPv6SrcIP,
	}

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
			rm.checkAndUpdateRoutes(state)
		}
	}
}

// routesChanged checks if any route parameters have changed
func (s *monitorState) routesChanged(gw, srcIP, ipv6gw, ipv6src string) bool {
	return gw != s.lastGW || srcIP != s.lastSrcIP || ipv6gw != s.lastIPv6GW || ipv6src != s.lastIPv6SrcIP
}

// checkAndUpdateRoutes checks if routes need updating and reconfigures if needed
func (rm *RouteMonitor) checkAndUpdateRoutes(state *monitorState) {
	gw, iface, srcIP, err := GetDefaultGateway()
	if err != nil {
		// Default route might be temporarily missing
		return
	}

	ipv6gw, ipv6iface, ipv6src, _ := GetDefaultIPv6Gateway()

	// Check if anything changed
	if !state.routesChanged(gw, srcIP, ipv6gw, ipv6src) {
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

	// Reset routes using RouteManager (handles cleanup and setup with retry)
	if err := rm.routeManager.ResetRoutes(rm.ctx); err != nil {
		slog.Error("Failed to reset routes after network change", "error", err)
		return
	}

	state.lastGW = gw
	state.lastSrcIP = srcIP
	state.lastIPv6GW = ipv6gw
	state.lastIPv6SrcIP = ipv6src

	rm.logRoutesConfigured()
	slog.Info("WAN route changed, routes updated")
}

// logRoutesConfigured logs the current route configuration
func (rm *RouteMonitor) logRoutesConfigured() {
	routeInfo := rm.routeManager.GetRouteInfo()
	if routeInfo == nil {
		return
	}

	if routeInfo.OriginalIPv6GW != "" {
		slog.Info("Routes configured",
			"ipv4_iface", routeInfo.OriginalIface,
			"ipv4_src", routeInfo.OriginalSrcIP,
			"ipv4_gw", routeInfo.OriginalGW,
			"ipv6_iface", routeInfo.OriginalIPv6Iface,
			"ipv6_src", routeInfo.OriginalIPv6SrcIP,
			"ipv6_gw", routeInfo.OriginalIPv6GW,
			"tunnel", "IPv4+IPv6")
	} else {
		slog.Info("Routes configured",
			"ipv4_iface", routeInfo.OriginalIface,
			"ipv4_src", routeInfo.OriginalSrcIP,
			"ipv4_gw", routeInfo.OriginalGW,
			"tunnel", "IPv4+IPv6")
	}
}
