package tun

import "uproxy/internal/validation"

// IPVersion returns the IP version (4 or 6) from a packet
func IPVersion(packet []byte) int {
	if len(packet) < 1 {
		return 0
	}
	return int(packet[0] >> 4)
}

// ValidatePacket performs validation on an IP packet
// Returns true if the packet has valid IP headers (IPv4 or IPv6)
func ValidatePacket(packet []byte) bool {
	return validation.ValidateIPPacket(packet)
}
