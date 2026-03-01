package network

import (
	"fmt"
	"net"
)

// ExtractHost extracts the host from an address string that may or may not include a port.
// Returns the host portion, handling both "host:port" and "host" formats.
func ExtractHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port specified, return the address as-is
		return addr
	}
	return host
}

// ResolveToIPv4AndIPv6 resolves a server address to both IPv4 and IPv6 addresses.
// The address can be a hostname:port, IP:port, hostname, or IP.
// Returns the IPv4 and IPv6 addresses (either may be empty if not found).
func ResolveToIPv4AndIPv6(serverAddr string) (ipv4, ipv6 string, err error) {
	host := ExtractHost(serverAddr)

	// Check if it's already an IP
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return host, "", nil
		}
		return "", host, nil
	}

	// Resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve server address: %w", err)
	}

	if len(ips) == 0 {
		return "", "", fmt.Errorf("no IPs found for server address")
	}

	// Collect both IPv4 and IPv6
	for _, ip := range ips {
		if ip.To4() != nil && ipv4 == "" {
			ipv4 = ip.String()
		} else if ip.To4() == nil && ipv6 == "" {
			ipv6 = ip.String()
		}
	}

	return ipv4, ipv6, nil
}
