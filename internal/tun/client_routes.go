package tun

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
)

// RouteInfo stores routing information for cleanup
type RouteInfo struct {
	ServerIP       string
	OriginalGW     string
	OriginalIface  string
	OriginalIPv6GW string
	TunDevice      string
}

// GetDefaultGateway returns the default gateway IP and interface
func GetDefaultGateway() (gateway, iface string, err error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("failed to get default route: %w", err)
	}

	// Parse output like: "default via 10.0.0.1 dev wlan0 proto dhcp src 10.0.0.118 metric 600"
	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			gateway = fields[i+1]
		}
		if field == "dev" && i+1 < len(fields) {
			iface = fields[i+1]
		}
	}

	if gateway == "" || iface == "" {
		return "", "", fmt.Errorf("could not parse default gateway")
	}

	return gateway, iface, nil
}

// GetDefaultIPv6Gateway returns the default IPv6 gateway
func GetDefaultIPv6Gateway() (gateway string, err error) {
	cmd := exec.Command("ip", "-6", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// IPv6 might not be configured, that's okay
		return "", nil
	}

	// Parse output like: "default via fe80::1 dev wlan0 proto ra metric 600"
	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", nil
}

// ResolveServerIP resolves a server address (hostname:port or IP:port) to an IP
func ResolveServerIP(serverAddr string) (string, error) {
	// Strip port if present
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		// Maybe no port was specified
		host = serverAddr
	}

	// Check if it's already an IP
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// Resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve server address: %w", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IPs found for server address")
	}

	// Prefer IPv4
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	// Fall back to IPv6
	return ips[0].String(), nil
}

// SetupClientRoutes sets up routing to send all traffic through TUN
func SetupClientRoutes(serverAddr, tunDevice string) (*RouteInfo, error) {
	info := &RouteInfo{
		TunDevice: tunDevice,
	}

	// Get current default gateway
	gw, iface, err := GetDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to get default gateway: %w", err)
	}
	info.OriginalGW = gw
	info.OriginalIface = iface

	// Get IPv6 gateway if available
	ipv6gw, _ := GetDefaultIPv6Gateway()
	info.OriginalIPv6GW = ipv6gw

	// Resolve server IP
	serverIP, err := ResolveServerIP(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server IP: %w", err)
	}
	info.ServerIP = serverIP

	slog.Info("Setting up client routes", "server_ip", serverIP, "original_gw", gw, "original_iface", iface, "tun_device", tunDevice)

	// Add route for VPN server through original gateway (so VPN traffic doesn't loop)
	cmd := exec.Command("ip", "route", "add", serverIP, "via", gw, "dev", iface)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Route might already exist, check if it's a duplicate error
		if !strings.Contains(string(output), "File exists") {
			return nil, fmt.Errorf("failed to add server route: %w, output: %s", err, output)
		}
		slog.Warn("Server route already exists", "server_ip", serverIP)
	} else {
		slog.Info("Added server exception route", "server_ip", serverIP, "via", gw, "dev", iface)
	}

	// Add default route through TUN (IPv4)
	cmd = exec.Command("ip", "route", "add", "default", "dev", tunDevice, "metric", "100")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to add default IPv4 route: %w, output: %s", err, output)
	}
	slog.Info("Added default IPv4 route", "dev", tunDevice)

	// Add default route through TUN (IPv6) if IPv6 is available
	if ipv6gw != "" {
		cmd = exec.Command("ip", "-6", "route", "add", "default", "dev", tunDevice, "metric", "100")
		if output, err := cmd.CombinedOutput(); err != nil {
			// IPv6 might fail, log but don't error
			slog.Warn("Failed to add default IPv6 route", "error", err, "output", string(output))
		} else {
			slog.Info("Added default IPv6 route", "dev", tunDevice)
		}
	}

	return info, nil
}

// CleanupClientRoutes removes the routes added by SetupClientRoutes
func CleanupClientRoutes(info *RouteInfo) {
	if info == nil {
		return
	}

	slog.Info("Cleaning up client routes", "server_ip", info.ServerIP, "tun_device", info.TunDevice)

	// Remove default route through TUN (IPv4)
	cmd := exec.Command("ip", "route", "del", "default", "dev", info.TunDevice, "metric", "100")
	if err := cmd.Run(); err != nil {
		slog.Warn("Failed to remove default IPv4 route", "error", err)
	} else {
		slog.Info("Removed default IPv4 route", "dev", info.TunDevice)
	}

	// Remove default route through TUN (IPv6)
	if info.OriginalIPv6GW != "" {
		cmd = exec.Command("ip", "-6", "route", "del", "default", "dev", info.TunDevice, "metric", "100")
		if err := cmd.Run(); err != nil {
			slog.Warn("Failed to remove default IPv6 route", "error", err)
		} else {
			slog.Info("Removed default IPv6 route", "dev", info.TunDevice)
		}
	}

	// Remove server exception route
	if info.ServerIP != "" && info.OriginalGW != "" && info.OriginalIface != "" {
		cmd = exec.Command("ip", "route", "del", info.ServerIP, "via", info.OriginalGW, "dev", info.OriginalIface)
		if err := cmd.Run(); err != nil {
			slog.Warn("Failed to remove server route", "error", err)
		} else {
			slog.Info("Removed server exception route", "server_ip", info.ServerIP)
		}
	}

	slog.Info("Client routes cleaned up")
}
