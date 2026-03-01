package tun

// IPVersion returns the IP version (4 or 6) from a packet
func IPVersion(packet []byte) int {
	if len(packet) < 1 {
		return 0
	}
	return int(packet[0] >> 4)
}

// ValidatePacket performs basic validation on an IP packet
func ValidatePacket(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	version := IPVersion(packet)
	if version == 4 {
		return len(packet) >= 20
	} else if version == 6 {
		return len(packet) >= 40
	}
	return false
}
