package tun

import "uproxy/internal/validation"

// ValidatePacket performs validation on an IP packet
// Returns true if the packet has valid IP headers (IPv4 or IPv6)
func ValidatePacket(packet []byte) bool {
	return validation.ValidateIPPacket(packet)
}
