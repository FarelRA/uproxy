package tun

import (
	"encoding/binary"
	"net"
)

// buildTCPResponsePacket constructs a complete TCP/IP packet for response
func buildTCPResponsePacket(info *PacketInfo, payload []byte) []byte {
	var packet []byte

	if info.Version == 4 {
		// Build IPv4 header
		ipHeader := make([]byte, 20)
		ipHeader[0] = 0x45                 // Version 4, IHL 5
		ipHeader[1] = 0                    // DSCP/ECN
		totalLen := 20 + 20 + len(payload) // IP header + TCP header + payload
		binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
		binary.BigEndian.PutUint16(ipHeader[4:6], 0) // ID
		binary.BigEndian.PutUint16(ipHeader[6:8], 0) // Flags/Fragment
		ipHeader[8] = 64                             // TTL
		ipHeader[9] = ProtocolTCP                    // Protocol
		// Checksum will be calculated later
		copy(ipHeader[12:16], net.ParseIP(info.DstIP).To4()) // Swap src/dst
		copy(ipHeader[16:20], net.ParseIP(info.SrcIP).To4())

		// Calculate IP checksum
		binary.BigEndian.PutUint16(ipHeader[10:12], ipChecksum(ipHeader))

		// Build TCP header (simplified - minimum 20 bytes)
		tcpHeader := make([]byte, 20)
		binary.BigEndian.PutUint16(tcpHeader[0:2], info.DstPort) // Swap src/dst
		binary.BigEndian.PutUint16(tcpHeader[2:4], info.SrcPort)
		binary.BigEndian.PutUint32(tcpHeader[4:8], 0)       // Seq number (should track state)
		binary.BigEndian.PutUint32(tcpHeader[8:12], 0)      // Ack number (should track state)
		tcpHeader[12] = 0x50                                // Data offset (5 * 4 = 20 bytes)
		tcpHeader[13] = 0x18                                // Flags: PSH, ACK
		binary.BigEndian.PutUint16(tcpHeader[14:16], 65535) // Window
		// Checksum will be calculated later
		binary.BigEndian.PutUint16(tcpHeader[18:20], 0) // Urgent pointer

		// Calculate TCP checksum with pseudo-header
		pseudoHeader := make([]byte, 12)
		copy(pseudoHeader[0:4], ipHeader[12:16]) // Source IP
		copy(pseudoHeader[4:8], ipHeader[16:20]) // Dest IP
		pseudoHeader[8] = 0                      // Reserved
		pseudoHeader[9] = ProtocolTCP            // Protocol
		binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(20+len(payload)))

		tcpData := append(pseudoHeader, tcpHeader...)
		tcpData = append(tcpData, payload...)
		binary.BigEndian.PutUint16(tcpHeader[16:18], ipChecksum(tcpData))

		packet = append(ipHeader, tcpHeader...)
		packet = append(packet, payload...)
	} else {
		// IPv6 - simplified implementation
		// TODO: Implement proper IPv6 packet construction
		packet = payload
	}

	return packet
}

// buildUDPResponsePacket constructs a complete UDP/IP packet for response
func buildUDPResponsePacket(info *PacketInfo, payload []byte) []byte {
	var packet []byte

	if info.Version == 4 {
		// Build IPv4 header
		ipHeader := make([]byte, 20)
		ipHeader[0] = 0x45                // Version 4, IHL 5
		ipHeader[1] = 0                   // DSCP/ECN
		totalLen := 20 + 8 + len(payload) // IP header + UDP header + payload
		binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
		binary.BigEndian.PutUint16(ipHeader[4:6], 0)         // ID
		binary.BigEndian.PutUint16(ipHeader[6:8], 0)         // Flags/Fragment
		ipHeader[8] = 64                                     // TTL
		ipHeader[9] = ProtocolUDP                            // Protocol
		copy(ipHeader[12:16], net.ParseIP(info.DstIP).To4()) // Swap src/dst
		copy(ipHeader[16:20], net.ParseIP(info.SrcIP).To4())

		// Calculate IP checksum
		binary.BigEndian.PutUint16(ipHeader[10:12], ipChecksum(ipHeader))

		// Build UDP header
		udpHeader := make([]byte, 8)
		binary.BigEndian.PutUint16(udpHeader[0:2], info.DstPort) // Swap src/dst
		binary.BigEndian.PutUint16(udpHeader[2:4], info.SrcPort)
		binary.BigEndian.PutUint16(udpHeader[4:6], uint16(8+len(payload))) // Length
		binary.BigEndian.PutUint16(udpHeader[6:8], 0)                      // Checksum (optional for IPv4)

		// Calculate UDP checksum with pseudo-header
		pseudoHeader := make([]byte, 12)
		copy(pseudoHeader[0:4], ipHeader[12:16]) // Source IP
		copy(pseudoHeader[4:8], ipHeader[16:20]) // Dest IP
		pseudoHeader[8] = 0                      // Reserved
		pseudoHeader[9] = ProtocolUDP            // Protocol
		binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(8+len(payload)))

		udpData := append(pseudoHeader, udpHeader...)
		udpData = append(udpData, payload...)
		checksum := ipChecksum(udpData)
		if checksum == 0 {
			checksum = 0xFFFF // UDP checksum 0 means no checksum
		}
		binary.BigEndian.PutUint16(udpHeader[6:8], checksum)

		packet = append(ipHeader, udpHeader...)
		packet = append(packet, payload...)
	} else {
		// IPv6 - simplified implementation
		// TODO: Implement proper IPv6 packet construction
		packet = payload
	}

	return packet
}

// buildICMPResponsePacket constructs a complete ICMP/IP packet for response
func buildICMPResponsePacket(info *PacketInfo, icmpData []byte) []byte {
	// Build IPv4 header
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version 4, IHL 5
	ipHeader[1] = 0    // DSCP/ECN
	totalLen := 20 + len(icmpData)
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHeader[4:6], 0)         // ID
	binary.BigEndian.PutUint16(ipHeader[6:8], 0)         // Flags/Fragment
	ipHeader[8] = 64                                     // TTL
	ipHeader[9] = ProtocolICMP                           // Protocol
	copy(ipHeader[12:16], net.ParseIP(info.DstIP).To4()) // Swap src/dst
	copy(ipHeader[16:20], net.ParseIP(info.SrcIP).To4())

	// Calculate IP checksum
	binary.BigEndian.PutUint16(ipHeader[10:12], ipChecksum(ipHeader))

	packet := append(ipHeader, icmpData...)
	return packet
}

// buildICMPv6ResponsePacket constructs a complete ICMPv6/IPv6 packet for response
func buildICMPv6ResponsePacket(info *PacketInfo, icmpData []byte) []byte {
	// Build IPv6 header (40 bytes)
	ipHeader := make([]byte, 40)
	ipHeader[0] = 0x60 // Version 6
	// Traffic class and flow label (bytes 1-3) = 0
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(len(icmpData))) // Payload length
	ipHeader[6] = ProtocolICMPv6                                     // Next header
	ipHeader[7] = 64                                                 // Hop limit

	srcIP := net.ParseIP(info.DstIP).To16() // Swap src/dst
	dstIP := net.ParseIP(info.SrcIP).To16()
	copy(ipHeader[8:24], srcIP)
	copy(ipHeader[24:40], dstIP)

	packet := append(ipHeader, icmpData...)
	return packet
}

// ipChecksum calculates the Internet Checksum (RFC 1071)
func ipChecksum(data []byte) uint16 {
	var sum uint32

	// Add up 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Add remaining byte if odd length
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}
