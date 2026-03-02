package tun

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"uproxy/internal/network"
	"uproxy/internal/routing"
)

// RouteInfo stores routing information for cleanup
type RouteInfo struct {
	ServerIPv4        string
	ServerIPv6        string
	OriginalGW        string
	OriginalIface     string
	OriginalSrcIP     string
	OriginalIPv6GW    string
	OriginalIPv6Iface string
	OriginalIPv6SrcIP string
	TunDevice         string
}

// GetDefaultGateway returns the default gateway IP, interface, and source IP
func GetDefaultGateway() (gateway, iface, srcIP string, err error) {
	info, err := routing.GetDefaultRoute()
	if err != nil {
		return "", "", "", err
	}
	return info.Gateway, info.Interface, info.SrcIP, nil
}

// GetDefaultIPv6Gateway returns the default IPv6 gateway, interface, and source IP
func GetDefaultIPv6Gateway() (gateway, iface, srcIP string, err error) {
	info, err := routing.GetDefaultIPv6Route()
	if err != nil {
		return "", "", "", err
	}
	return info.Gateway, info.Interface, info.SrcIP, nil
}

// ResolveServerIPs resolves a server address (hostname:port or IP:port) to IPv4 and IPv6
func ResolveServerIPs(serverAddr string) (ipv4, ipv6 string, err error) {
	return network.ResolveToIPv4AndIPv6(serverAddr)
}

// SetupClientRoutes sets up routing to send all traffic through TUN
func SetupClientRoutes(serverAddr, tunDevice string) (*RouteInfo, error) {
	info := &RouteInfo{
		TunDevice: tunDevice,
	}

	// Get current default gateway (IPv4)
	gw, iface, srcIP, err := GetDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to get default gateway: %w", err)
	}
	info.OriginalGW = gw
	info.OriginalIface = iface
	info.OriginalSrcIP = srcIP

	// Get IPv6 gateway if available
	ipv6gw, ipv6iface, ipv6src, _ := GetDefaultIPv6Gateway()
	info.OriginalIPv6GW = ipv6gw
	info.OriginalIPv6Iface = ipv6iface
	info.OriginalIPv6SrcIP = ipv6src

	// Resolve server IPs (both IPv4 and IPv6)
	serverIPv4, serverIPv6, err := ResolveServerIPs(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server IPs: %w", err)
	}
	info.ServerIPv4 = serverIPv4
	info.ServerIPv6 = serverIPv6

	slog.Info("Setting up client routes",
		"server_ipv4", serverIPv4,
		"server_ipv6", serverIPv6,
		"original_gw", gw,
		"original_iface", iface,
		"original_src", srcIP,
		"tun_device", tunDevice)

	// Add server exception routes
	if err := addServerExceptionRoutes(info); err != nil {
		return nil, err
	}

	// Add default routes through TUN
	if err := addDefaultTUNRoutes(tunDevice, ipv6gw); err != nil {
		return nil, err
	}

	return info, nil
}

// addServerExceptionRoutes adds routes for server IPs through original gateway
func addServerExceptionRoutes(info *RouteInfo) error {
	// Add route for VPN server IPv4 through original gateway (so VPN traffic doesn't loop)
	if info.ServerIPv4 != "" && info.OriginalGW != "" {
		args := []string{"route", "replace", info.ServerIPv4, "via", info.OriginalGW, "dev", info.OriginalIface}
		if info.OriginalSrcIP != "" {
			args = append(args, "src", info.OriginalSrcIP)
		}
		args = append(args, "metric", "600")

		cmd := exec.Command("ip", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Route might already exist, check if it's a duplicate error
			if !strings.Contains(string(output), "File exists") {
				return fmt.Errorf("failed to add server IPv4 route: %w, output: %s", err, output)
			}
			slog.Warn("Server IPv4 route already exists", "server_ip", info.ServerIPv4)
		} else {
			slog.Info("Added server IPv4 exception route", "server_ip", info.ServerIPv4, "via", info.OriginalGW, "dev", info.OriginalIface, "src", info.OriginalSrcIP)
		}
	}

	// Add route for VPN server IPv6 through original gateway (if IPv6 is available)
	if info.ServerIPv6 != "" && info.OriginalIPv6GW != "" {
		args := []string{"-6", "route", "replace", info.ServerIPv6, "via", info.OriginalIPv6GW, "dev", info.OriginalIPv6Iface}
		if info.OriginalIPv6SrcIP != "" {
			args = append(args, "src", info.OriginalIPv6SrcIP)
		}
		args = append(args, "metric", "600")

		cmd := exec.Command("ip", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(output), "File exists") {
				slog.Warn("Failed to add server IPv6 route", "error", err, "output", string(output))
			} else {
				slog.Warn("Server IPv6 route already exists", "server_ip", info.ServerIPv6)
			}
		} else {
			slog.Info("Added server IPv6 exception route", "server_ip", info.ServerIPv6, "via", info.OriginalIPv6GW, "dev", info.OriginalIPv6Iface, "src", info.OriginalIPv6SrcIP)
		}
	}

	return nil
}

// addDefaultTUNRoutes adds default routes through TUN device
func addDefaultTUNRoutes(tunDevice, ipv6gw string) error {
	// Add default route through TUN (IPv4) - no metric for highest priority
	cmd := exec.Command("ip", "route", "replace", "default", "dev", tunDevice)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add default IPv4 route: %w, output: %s", err, output)
	}
	slog.Info("Added default IPv4 route", "dev", tunDevice)

	// Add default route through TUN (IPv6) if IPv6 is available
	if ipv6gw != "" {
		// Use 'replace' instead of 'add' to handle existing routes
		cmd = exec.Command("ip", "-6", "route", "replace", "default", "dev", tunDevice)
		if output, err := cmd.CombinedOutput(); err != nil {
			// IPv6 might fail, log but don't error
			slog.Warn("Failed to add default IPv6 route", "error", err, "output", string(output))
		} else {
			slog.Info("Added default IPv6 route", "dev", tunDevice)
		}
	}

	return nil
}

// CleanupClientRoutes removes the routes added by SetupClientRoutes
func CleanupClientRoutes(info *RouteInfo) {
	if info == nil {
		return
	}

	slog.Info("Cleaning up client routes",
		"server_ipv4", info.ServerIPv4,
		"server_ipv6", info.ServerIPv6,
		"tun_device", info.TunDevice)

	// Remove default route through TUN (IPv4)
	cmd := exec.Command("ip", "route", "del", "default", "dev", info.TunDevice)
	if err := cmd.Run(); err != nil {
		slog.Warn("Failed to remove default IPv4 route", "error", err)
	} else {
		slog.Info("Removed default IPv4 route", "dev", info.TunDevice)
	}

	// Remove default route through TUN (IPv6)
	if info.OriginalIPv6GW != "" {
		cmd = exec.Command("ip", "-6", "route", "del", "default", "dev", info.TunDevice)
		if err := cmd.Run(); err != nil {
			slog.Warn("Failed to remove default IPv6 route", "error", err)
		} else {
			slog.Info("Removed default IPv6 route", "dev", info.TunDevice)
		}
	}

	// Remove server IPv4 exception route
	if info.ServerIPv4 != "" && info.OriginalGW != "" && info.OriginalIface != "" {
		args := []string{"route", "del", info.ServerIPv4, "via", info.OriginalGW, "dev", info.OriginalIface}
		if info.OriginalSrcIP != "" {
			args = append(args, "src", info.OriginalSrcIP)
		}
		args = append(args, "metric", "600")

		cmd = exec.Command("ip", args...)
		if err := cmd.Run(); err != nil {
			slog.Warn("Failed to remove server IPv4 route", "error", err)
		} else {
			slog.Info("Removed server IPv4 exception route", "server_ip", info.ServerIPv4)
		}
	}

	// Remove server IPv6 exception route
	if info.ServerIPv6 != "" && info.OriginalIPv6GW != "" && info.OriginalIPv6Iface != "" {
		args := []string{"-6", "route", "del", info.ServerIPv6, "via", info.OriginalIPv6GW, "dev", info.OriginalIPv6Iface}
		if info.OriginalIPv6SrcIP != "" {
			args = append(args, "src", info.OriginalIPv6SrcIP)
		}
		args = append(args, "metric", "600")

		cmd = exec.Command("ip", args...)
		if err := cmd.Run(); err != nil {
			slog.Warn("Failed to remove server IPv6 route", "error", err)
		} else {
			slog.Info("Removed server IPv6 exception route", "server_ip", info.ServerIPv6)
		}
	}

	slog.Info("Client routes cleaned up")
}
