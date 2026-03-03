package tun

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
)

// AddRoute adds a route through the TUN interface
func AddRoute(dest, ifaceName string) error {
	// Detect if this is an IPv6 route
	isIPv6 := strings.Contains(dest, ":")

	switch runtime.GOOS {
	case "linux":
		args := []string{"route", "replace", dest, "dev", ifaceName}
		if isIPv6 {
			args = []string{"-6", "route", "replace", dest, "dev", ifaceName}
		}
		cmd := exec.Command("ip", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add route %s: %w, output: %s", dest, err, output)
		}
	case "darwin":
		// Parse destination to get network and gateway
		args := []string{"add"}
		if isIPv6 {
			args = append(args, "-inet6")
		}
		args = append(args, "-net", dest, "-interface", ifaceName)
		cmd := exec.Command("route", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add route %s: %w, output: %s", dest, err, output)
		}
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	slog.Info("Route added", "dest", dest, "interface", ifaceName)
	return nil
}

// ParseRoutes parses comma-separated route list
func ParseRoutes(routes string) []string {
	if routes == "" {
		return nil
	}

	parts := strings.Split(routes, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
