package tun

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
	if len(packet) < 20 {
		return false
	}

	version := IPVersion(packet)

	if version == 4 {
		// IPv4 validation
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
	} else if version == 6 {
		// IPv6 validation - fixed 40 byte header
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

	return false
}
