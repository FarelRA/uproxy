package tun

import (
	"encoding/binary"
	"fmt"
)

// IPVersion returns the IP version (4 or 6) from a packet
func IPVersion(packet []byte) int {
	if len(packet) < 1 {
		return 0
	}
	return int(packet[0] >> 4)
}

// ParseIPv4Header extracts source and destination IPs from an IPv4 packet
func ParseIPv4Header(packet []byte) (src, dst string, protocol uint8, err error) {
	if len(packet) < 20 {
		return "", "", 0, fmt.Errorf("packet too short for IPv4 header")
	}

	version := packet[0] >> 4
	if version != 4 {
		return "", "", 0, fmt.Errorf("not an IPv4 packet")
	}

	protocol = packet[9]
	src = fmt.Sprintf("%d.%d.%d.%d", packet[12], packet[13], packet[14], packet[15])
	dst = fmt.Sprintf("%d.%d.%d.%d", packet[16], packet[17], packet[18], packet[19])

	return src, dst, protocol, nil
}

// ParseIPv6Header extracts source and destination IPs from an IPv6 packet
func ParseIPv6Header(packet []byte) (src, dst string, protocol uint8, err error) {
	if len(packet) < 40 {
		return "", "", 0, fmt.Errorf("packet too short for IPv6 header")
	}

	version := packet[0] >> 4
	if version != 6 {
		return "", "", 0, fmt.Errorf("not an IPv6 packet")
	}

	protocol = packet[6]

	srcBytes := packet[8:24]
	dstBytes := packet[24:40]

	src = formatIPv6(srcBytes)
	dst = formatIPv6(dstBytes)

	return src, dst, protocol, nil
}

func formatIPv6(ip []byte) string {
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		binary.BigEndian.Uint16(ip[0:2]),
		binary.BigEndian.Uint16(ip[2:4]),
		binary.BigEndian.Uint16(ip[4:6]),
		binary.BigEndian.Uint16(ip[6:8]),
		binary.BigEndian.Uint16(ip[8:10]),
		binary.BigEndian.Uint16(ip[10:12]),
		binary.BigEndian.Uint16(ip[12:14]),
		binary.BigEndian.Uint16(ip[14:16]))
}

// ProtocolName returns the protocol name for common protocols
func ProtocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("Proto%d", protocol)
	}
}
