package tun

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	ProtocolICMP   = 1
	ProtocolTCP    = 6
	ProtocolUDP    = 17
	ProtocolICMPv6 = 58
)

// FlowKey uniquely identifies a network flow (connection or session)
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

func (f FlowKey) String() string {
	if f.SrcPort == 0 && f.DstPort == 0 {
		return fmt.Sprintf("%s->%s/%s", f.SrcIP, f.DstIP, ProtocolName(f.Protocol))
	}
	return fmt.Sprintf("%s:%d->%s:%d/%s", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, ProtocolName(f.Protocol))
}

// PacketInfo contains parsed packet information
type PacketInfo struct {
	Version    int
	Protocol   uint8
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	HeaderLen  int
	PayloadLen int
	FlowKey    FlowKey
}

// IPVersion returns the IP version (4 or 6) from a packet
func IPVersion(packet []byte) int {
	if len(packet) < 1 {
		return 0
	}
	return int(packet[0] >> 4)
}

// ParsePacket extracts complete packet information including ports
func ParsePacket(packet []byte) (*PacketInfo, error) {
	if len(packet) < 1 {
		return nil, fmt.Errorf("empty packet")
	}

	version := IPVersion(packet)
	switch version {
	case 4:
		return parseIPv4Packet(packet)
	case 6:
		return parseIPv6Packet(packet)
	default:
		return nil, fmt.Errorf("unknown IP version: %d", version)
	}
}

func parseIPv4Packet(packet []byte) (*PacketInfo, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("packet too short for IPv4 header")
	}

	info := &PacketInfo{Version: 4}

	ihl := int(packet[0]&0x0F) * 4
	if ihl < 20 {
		return nil, fmt.Errorf("invalid IPv4 header length: %d", ihl)
	}
	info.HeaderLen = ihl

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	info.PayloadLen = totalLen - ihl

	info.Protocol = packet[9]
	info.SrcIP = net.IPv4(packet[12], packet[13], packet[14], packet[15]).String()
	info.DstIP = net.IPv4(packet[16], packet[17], packet[18], packet[19]).String()

	if len(packet) < ihl {
		return nil, fmt.Errorf("packet truncated at IP header")
	}

	payload := packet[ihl:]
	if err := extractPorts(info, payload); err != nil {
		return nil, err
	}

	info.FlowKey = FlowKey{
		SrcIP:    info.SrcIP,
		DstIP:    info.DstIP,
		SrcPort:  info.SrcPort,
		DstPort:  info.DstPort,
		Protocol: info.Protocol,
	}

	return info, nil
}

func parseIPv6Packet(packet []byte) (*PacketInfo, error) {
	if len(packet) < 40 {
		return nil, fmt.Errorf("packet too short for IPv6 header")
	}

	info := &PacketInfo{Version: 6, HeaderLen: 40}

	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	info.PayloadLen = payloadLen

	info.Protocol = packet[6]

	srcIP := net.IP(packet[8:24])
	dstIP := net.IP(packet[24:40])
	info.SrcIP = srcIP.String()
	info.DstIP = dstIP.String()

	if len(packet) < 40 {
		return nil, fmt.Errorf("packet truncated at IPv6 header")
	}

	payload := packet[40:]
	if err := extractPorts(info, payload); err != nil {
		return nil, err
	}

	info.FlowKey = FlowKey{
		SrcIP:    info.SrcIP,
		DstIP:    info.DstIP,
		SrcPort:  info.SrcPort,
		DstPort:  info.DstPort,
		Protocol: info.Protocol,
	}

	return info, nil
}

func extractPorts(info *PacketInfo, payload []byte) error {
	switch info.Protocol {
	case ProtocolTCP:
		if len(payload) < 4 {
			return fmt.Errorf("TCP header truncated")
		}
		info.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		info.DstPort = binary.BigEndian.Uint16(payload[2:4])

	case ProtocolUDP:
		if len(payload) < 4 {
			return fmt.Errorf("UDP header truncated")
		}
		info.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		info.DstPort = binary.BigEndian.Uint16(payload[2:4])

	case ProtocolICMP, ProtocolICMPv6:
		// ICMP doesn't have ports, leave as 0

	default:
		// Unknown protocol, no port extraction
	}

	return nil
}

// ParseIPv4Header extracts source and destination IPs from an IPv4 packet (legacy)
func ParseIPv4Header(packet []byte) (src, dst string, protocol uint8, err error) {
	info, err := parseIPv4Packet(packet)
	if err != nil {
		return "", "", 0, err
	}
	return info.SrcIP, info.DstIP, info.Protocol, nil
}

// ParseIPv6Header extracts source and destination IPs from an IPv6 packet (legacy)
func ParseIPv6Header(packet []byte) (src, dst string, protocol uint8, err error) {
	info, err := parseIPv6Packet(packet)
	if err != nil {
		return "", "", 0, err
	}
	return info.SrcIP, info.DstIP, info.Protocol, nil
}

// ProtocolName returns the protocol name for common protocols
func ProtocolName(protocol uint8) string {
	switch protocol {
	case ProtocolICMP:
		return "ICMP"
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("Proto%d", protocol)
	}
}
