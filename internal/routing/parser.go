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

// commandExecutor is an interface for executing commands (for testing)
type commandExecutor interface {
	CombinedOutput(name string, args ...string) ([]byte, error)
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

// defaultExecutor implements commandExecutor using os/exec
type defaultExecutor struct{}

func (e *defaultExecutor) CombinedOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func (e *defaultExecutor) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

var executor commandExecutor = &defaultExecutor{}

// RouteInfo contains parsed route information
type RouteInfo struct {
	Gateway   string
	Interface string
	SrcIP     string
}

// routeKeywords contains keywords that should not be used as route values
var routeKeywords = map[string]bool{
	"via": true, "dev": true, "src": true, "proto": true,
	"metric": true, "scope": true, "link": true, "default": true,
}

// isRouteKeyword checks if a field is a route keyword
func isRouteKeyword(field string) bool {
	return routeKeywords[field]
}

// ParseIPRouteOutput parses the output of "ip route" commands
// Handles output like: "default via 10.0.0.1 dev wlan0 src 10.0.0.118 metric 600"
func ParseIPRouteOutput(output string) (*RouteInfo, error) {
	fields := strings.Fields(output)
	info := &RouteInfo{}

	for i, field := range fields {
		if field == "via" && i+1 < len(fields) && info.Gateway == "" {
			nextField := fields[i+1]
			if !isRouteKeyword(nextField) {
				info.Gateway = nextField
			}
		}
		if field == "dev" && i+1 < len(fields) && info.Interface == "" {
			nextField := fields[i+1]
			if !isRouteKeyword(nextField) {
				info.Interface = nextField
			}
		}
		if field == "src" && i+1 < len(fields) && info.SrcIP == "" {
			nextField := fields[i+1]
			if !isRouteKeyword(nextField) {
				info.SrcIP = nextField
			}
		}
	}

	// Interface is required, but gateway is optional (e.g., for local routes)
	if info.Interface == "" {
		return nil, fmt.Errorf("could not parse route information from: %s", output)
	}

	return info, nil
}

// GetDefaultRoute retrieves the default IPv4 route information
func GetDefaultRoute() (*RouteInfo, error) {
	output, err := executor.CombinedOutput("ip", "route", "show", "default")
	if err != nil {
		return nil, fmt.Errorf("failed to get default route: %w", err)
	}

	info, err := ParseIPRouteOutput(string(output))
	if err != nil {
		return nil, err
	}

	return info, nil
}

// GetDefaultIPv6Route retrieves the default IPv6 route information
// Returns nil error with empty RouteInfo if IPv6 is not configured
func GetDefaultIPv6Route() (*RouteInfo, error) {
	output, err := executor.CombinedOutput("ip", "-6", "route", "show", "default")
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
	output, err := executor.Output(ctx, "ip", "route", "get", host)
	if err != nil {
		return nil, fmt.Errorf("failed to get route to %s: %w", host, err)
	}

	return ParseIPRouteOutput(string(output))
}
