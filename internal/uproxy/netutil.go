package uproxy

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"time"
)

// networkInterface abstracts net.Interface operations for testing
type networkInterface interface {
	Addrs() ([]net.Addr, error)
}

// realNetworkInterface wraps net.Interface
type realNetworkInterface struct {
	iface *net.Interface
}

func (r *realNetworkInterface) Addrs() ([]net.Addr, error) {
	return r.iface.Addrs()
}

// interfaceByNameFunc allows mocking net.InterfaceByName for testing
var interfaceByNameFunc = func(name string) (networkInterface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return &realNetworkInterface{iface: iface}, nil
}

// IsRoot checks if the current process has root/administrator privileges.
// Returns true if running as root (Unix) or administrator (Windows).
func IsRoot() bool {
	if runtime.GOOS == "windows" {
		// On Windows, this is more complex and would require syscalls
		// For now, assume non-root on Windows
		return false
	}
	// On Unix-like systems, check if effective user ID is 0
	return os.Geteuid() == 0
}

// firstIPOfInterface is a generic helper that returns the first IP of a given version
func firstIPOfInterface(ifaceName string, version int) (net.IP, error) {
	iface, err := interfaceByNameFunc(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for %s: %w", ifaceName, err)
	}

	versionName := "IPv4"
	if version == 6 {
		versionName = "IPv6"
	}

	slog.Debug("Searching for IP address on interface", "interface", ifaceName, "version", versionName, "addresses_count", len(addrs))

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		slog.Debug("Examining address", "interface", ifaceName, "address", ip.String())

		if version == 4 {
			if ip4 := ip.To4(); ip4 != nil {
				slog.Debug("Found matching IPv4 address", "interface", ifaceName, "ip", ip4.String())
				return ip4, nil
			}
		} else if version == 6 {
			// Check if it's IPv6 (not IPv4) and not link-local
			if ip.To4() == nil && ip.To16() != nil && !ip.IsLinkLocalUnicast() {
				slog.Debug("Found matching IPv6 address", "interface", ifaceName, "ip", ip.String())
				return ip, nil
			}
		}
	}
	slog.Warn("No matching IP address found", "interface", ifaceName, "version", versionName, "addresses_examined", len(addrs))
	return nil, fmt.Errorf("no %s address found on interface %s", versionName, ifaceName)
}

// FirstIPv4OfInterface iterates through all IP addresses of a given network interface
// and returns the very first valid IPv4 address it finds.
// This is essential for forcing the proxy's outbound traffic (both TCP and UDP)
// through a specific VPN tunnel or network interface (e.g., tun0).
func FirstIPv4OfInterface(ifaceName string) (net.IP, error) {
	return firstIPOfInterface(ifaceName, 4)
}

// FirstIPv6OfInterface iterates through all IP addresses of a given network interface
// and returns the very first valid IPv6 address it finds (excluding link-local).
func FirstIPv6OfInterface(ifaceName string) (net.IP, error) {
	return firstIPOfInterface(ifaceName, 6)
}

// FirstIPOfInterface returns the first IP address (IPv4 or IPv6) of a given interface.
// It prefers IPv4 if available, otherwise returns IPv6.
func FirstIPOfInterface(ifaceName string) (net.IP, error) {
	// Try IPv4 first
	if ip, err := FirstIPv4OfInterface(ifaceName); err == nil {
		return ip, nil
	}
	// Fall back to IPv6
	return FirstIPv6OfInterface(ifaceName)
}

// GetInterfaceIPs returns both IPv4 and IPv6 addresses for an interface.
func GetInterfaceIPs(ifaceName string) (ipv4 net.IP, ipv6 net.IP, err error) {
	iface, err := interfaceByNameFunc(ifaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get addresses for %s: %w", ifaceName, err)
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil && ipv4 == nil {
			ipv4 = ip4
		} else if ip.To4() == nil && ip.To16() != nil && !ip.IsLinkLocalUnicast() && ipv6 == nil {
			ipv6 = ip
		}
	}
	if ipv4 == nil && ipv6 == nil {
		return nil, nil, fmt.Errorf("no IP addresses found on interface %s", ifaceName)
	}
	return ipv4, ipv6, nil
}

// BindAddrForInterface parses a listening address (like ":6000" or "0.0.0.0:6000").
// If an interface name is provided, it replaces the wildcard host with the actual
// IP address of that interface to ensure strict binding. Supports both IPv4 and IPv6.
func BindAddrForInterface(addr, ifaceName string) (string, error) {
	if ifaceName == "" {
		return addr, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address %s: %w", addr, err)
	}
	// If the user provided a wildcard, bind strictly to the interface's IP
	if host == "" || host == "0.0.0.0" || host == "::" {
		ip, err := FirstIPOfInterface(ifaceName)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	return addr, nil
}

// CreateDialer creates a net.Dialer configured for the specified network type with optional interface binding.
// Supports both "tcp" and "udp" network types. If outbound interface is specified, binds the dialer to that interface's IP.
func CreateDialer(network, outbound string, dialTimeout time.Duration) (*net.Dialer, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	if outbound != "" {
		// Try to get IP from interface (supports both IPv4 and IPv6)
		ip, err := FirstIPOfInterface(outbound)
		if err != nil {
			return nil, err
		}

		switch network {
		case "tcp":
			dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: 0}
		case "udp":
			dialer.LocalAddr = &net.UDPAddr{IP: ip, Port: 0}
		}
	}
	return dialer, nil
}

// OptimizeUDPConn forces the OS-level UDP socket to allocate massive Read/Write
// buffers to safely accommodate high-throughput, high-BDP KCP window sizes
// without kernel-level packet drops.
func OptimizeUDPConn(conn *net.UDPConn, bufSize int) {
	if bufSize > 0 {
		if err := conn.SetReadBuffer(bufSize); err != nil {
			slog.Debug("Failed to set UDP read buffer size", "size", bufSize, "error", err)
		}
		if err := conn.SetWriteBuffer(bufSize); err != nil {
			slog.Debug("Failed to set UDP write buffer size", "size", bufSize, "error", err)
		}
	}
}
