package tun

import "net"

// ManagerInterface defines the interface for TUN device management.
// This allows for easier testing of TUN-related functionality.
type ManagerInterface interface {
	AllocateIP() (ipv4 string, ipv6 string, err error)
	RegisterClient(ipv4, ipv6 string, conn net.Conn) *ClientRoute
	UnregisterClient(ipv4, ipv6 string)
	Close() error
}

// Ensure TUNManager implements ManagerInterface
var _ ManagerInterface = (*TUNManager)(nil)
