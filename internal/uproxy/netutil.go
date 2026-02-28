package uproxy

import (
	"fmt"
	"net"
)

// FirstIPv4OfInterface iterates through all IP addresses of a given network interface
// and returns the very first valid IPv4 address it finds.
// This is essential for forcing the proxy's outbound traffic (both TCP and UDP)
// through a specific VPN tunnel or network interface (e.g., tun0).
func FirstIPv4OfInterface(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for %s: %w", ifaceName, err)
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address found on interface %s", ifaceName)
}

// BindAddrForInterface parses a listening address (like ":6000" or "0.0.0.0:6000").
// If an interface name is provided, it replaces the wildcard host with the actual
// IPv4 address of that interface to ensure strict binding.
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
		ip, err := FirstIPv4OfInterface(ifaceName)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	return addr, nil
}

// OptimizeUDPConn forces the OS-level UDP socket to allocate massive Read/Write
// buffers to safely accommodate high-throughput, high-BDP KCP window sizes
// without kernel-level packet drops.
func OptimizeUDPConn(conn *net.UDPConn, bufSize int) {
	if bufSize > 0 {
		_ = conn.SetReadBuffer(bufSize)
		_ = conn.SetWriteBuffer(bufSize)
	}
}
