// Package validation provides reusable validation functions for various data types
// and protocols used throughout the uproxy application.
package validation

import (
	"fmt"
	"net"

	"uproxy/internal/config"
	"uproxy/internal/uproxy"
)

// ValidateIPv4Packet validates an IPv4 packet structure
func ValidateIPv4Packet(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}

	// Check IHL (Internet Header Length) - minimum is 5 (20 bytes)
	ihl := int(packet[0] & 0x0F)
	if ihl < 5 {
		return false
	}

	headerLen := ihl * 4
	if len(packet) < headerLen {
		return false
	}

	// Validate total length field
	if len(packet) >= 4 {
		totalLen := int(packet[2])<<8 | int(packet[3])
		if totalLen < headerLen || totalLen > len(packet) {
			return false
		}
	}

	return true
}

// ValidateIPv6Packet validates an IPv6 packet structure
func ValidateIPv6Packet(packet []byte) bool {
	// IPv6 has a fixed 40 byte header
	if len(packet) < 40 {
		return false
	}

	// Validate payload length field
	payloadLen := int(packet[4])<<8 | int(packet[5])
	if 40+payloadLen > len(packet) {
		return false
	}

	return true
}

// ValidateIPPacket validates an IP packet (IPv4 or IPv6)
func ValidateIPPacket(packet []byte) bool {
	if len(packet) < 1 {
		return false
	}

	version := (packet[0] >> 4) & 0x0F

	switch version {
	case 4:
		return ValidateIPv4Packet(packet)
	case 6:
		return ValidateIPv6Packet(packet)
	default:
		return false
	}
}

// ValidateSOCKS5Version checks if the SOCKS version byte is valid (0x05)
func ValidateSOCKS5Version(version byte) bool {
	return version == 0x05
}

// ValidateSOCKS5AddressType checks if the SOCKS5 address type is valid
func ValidateSOCKS5AddressType(atyp byte) bool {
	switch atyp {
	case 1: // IPv4
		return true
	case 3: // Domain name
		return true
	case 4: // IPv6
		return true
	default:
		return false
	}
}

// ValidateSOCKS5Command checks if the SOCKS5 command is valid
func ValidateSOCKS5Command(cmd byte) bool {
	switch cmd {
	case 1: // CONNECT
		return true
	case 2: // BIND
		return true
	case 3: // UDP ASSOCIATE
		return true
	default:
		return false
	}
}

// ValidateClientMode validates the client mode configuration
func ValidateClientMode(cfg *config.ClientConfig) error {
	switch cfg.Mode {
	case "socks5":
		if cfg.ListenAddr == "" {
			return fmt.Errorf("--listen is required for socks5 mode")
		}
	case "tun":
		if !uproxy.IsRoot() {
			return fmt.Errorf("TUN mode requires root privileges. Run with sudo or use --mode socks5")
		}
	case "auto":
		// Will be resolved at runtime
	default:
		return fmt.Errorf("invalid mode: %s (must be 'auto', 'socks5', or 'tun')", cfg.Mode)
	}
	return nil
}

// ValidateIPAddress checks if a string is a valid IP address
func ValidateIPAddress(addr string) bool {
	return net.ParseIP(addr) != nil
}

// ValidatePort checks if a port number is valid (1-65535)
func ValidatePort(port int) bool {
	return port > 0 && port <= 65535
}
