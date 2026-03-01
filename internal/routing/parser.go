// Package routing provides utilities for parsing and managing system routing tables.
// It supports parsing route information from platform-specific commands and
// extracting gateway and interface details.
package routing

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// RouteInfo contains parsed route information
type RouteInfo struct {
	Gateway   string
	Interface string
	SrcIP     string
}

// ParseIPRouteOutput parses the output of "ip route" commands
// Handles output like: "default via 10.0.0.1 dev wlan0 src 10.0.0.118 metric 600"
func ParseIPRouteOutput(output string) (*RouteInfo, error) {
	fields := strings.Fields(output)
	info := &RouteInfo{}

	for i, field := range fields {
		if field == "via" && i+1 < len(fields) && info.Gateway == "" {
			info.Gateway = fields[i+1]
		}
		if field == "dev" && i+1 < len(fields) && info.Interface == "" {
			info.Interface = fields[i+1]
		}
		if field == "src" && i+1 < len(fields) && info.SrcIP == "" {
			info.SrcIP = fields[i+1]
		}
	}

	if info.Gateway == "" || info.Interface == "" {
		return nil, fmt.Errorf("could not parse route information from: %s", output)
	}

	return info, nil
}

// GetDefaultRoute retrieves the default IPv4 route information
func GetDefaultRoute() (*RouteInfo, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get default route: %w", err)
	}

	return ParseIPRouteOutput(string(output))
}

// GetDefaultIPv6Route retrieves the default IPv6 route information
// Returns nil error with empty RouteInfo if IPv6 is not configured
func GetDefaultIPv6Route() (*RouteInfo, error) {
	cmd := exec.Command("ip", "-6", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// IPv6 might not be configured, that's okay
		return &RouteInfo{}, nil
	}

	info, err := ParseIPRouteOutput(string(output))
	if err != nil {
		// IPv6 route parsing failed, return empty info (not an error)
		return &RouteInfo{}, nil
	}

	return info, nil
}

// GetRouteToHost retrieves route information for a specific host
func GetRouteToHost(ctx context.Context, host string) (*RouteInfo, error) {
	cmd := exec.CommandContext(ctx, "ip", "route", "get", host)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get route to %s: %w", host, err)
	}

	return ParseIPRouteOutput(string(output))
}
