package tun

import (
	"fmt"
	"log/slog"
	"net"

	"golang.org/x/sys/unix"
)

// PacketInjector injects IP packets into the system's network stack using raw sockets
type PacketInjector struct {
	fd4      int    // IPv4 raw socket
	fd6      int    // IPv6 raw socket
	outbound string // Optional outbound interface
	ifaceIdx int    // Interface index for outbound
}

// NewPacketInjector creates a new packet injector
func NewPacketInjector(outbound string) (*PacketInjector, error) {
	injector := &PacketInjector{
		outbound: outbound,
		fd4:      -1,
		fd6:      -1,
	}

	// Create IPv4 raw socket
	fd4, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv4 raw socket: %w (requires root/CAP_NET_RAW)", err)
	}
	injector.fd4 = fd4

	// Set IP_HDRINCL so we provide the complete IP header
	if err := unix.SetsockoptInt(fd4, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd4)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	// Create IPv6 raw socket
	fd6, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		slog.Warn("Failed to create IPv6 raw socket, IPv6 disabled", "error", err)
	} else {
		injector.fd6 = fd6
	}

	// Bind to outbound interface if specified
	if outbound != "" {
		iface, err := net.InterfaceByName(outbound)
		if err != nil {
			injector.Close()
			return nil, fmt.Errorf("failed to find interface %s: %w", outbound, err)
		}
		injector.ifaceIdx = iface.Index

		// Bind IPv4 socket to interface
		if err := unix.SetsockoptString(fd4, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, outbound); err != nil {
			injector.Close()
			return nil, fmt.Errorf("failed to bind IPv4 socket to %s: %w", outbound, err)
		}

		// Bind IPv6 socket to interface if available
		if fd6 >= 0 {
			if err := unix.SetsockoptString(fd6, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, outbound); err != nil {
				slog.Warn("Failed to bind IPv6 socket to interface", "interface", outbound, "error", err)
			}
		}

		slog.Info("Packet injector bound to interface", "interface", outbound)
	}

	return injector, nil
}

// Inject injects an IP packet into the system's network stack
func (p *PacketInjector) Inject(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short: %d bytes", len(packet))
	}

	version := IPVersion(packet)

	switch version {
	case 4:
		return p.injectIPv4(packet)
	case 6:
		return p.injectIPv6(packet)
	default:
		return fmt.Errorf("unknown IP version: %d", version)
	}
}

// injectIPv4 injects an IPv4 packet
func (p *PacketInjector) injectIPv4(packet []byte) error {
	if p.fd4 < 0 {
		return fmt.Errorf("IPv4 socket not available")
	}

	if len(packet) < 20 {
		return fmt.Errorf("IPv4 packet too short: %d bytes", len(packet))
	}

	// Extract destination IP from packet header (bytes 16-19)
	dstIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])

	// Create sockaddr
	sa := &unix.SockaddrInet4{
		Port: 0, // Raw socket doesn't use port
	}
	copy(sa.Addr[:], dstIP.To4())

	// Send packet - kernel handles routing, fragmentation, etc.
	err := unix.Sendto(p.fd4, packet, 0, sa)
	if err != nil {
		return fmt.Errorf("failed to send IPv4 packet: %w", err)
	}

	return nil
}

// injectIPv6 injects an IPv6 packet
func (p *PacketInjector) injectIPv6(packet []byte) error {
	if p.fd6 < 0 {
		return fmt.Errorf("IPv6 socket not available")
	}

	if len(packet) < 40 {
		return fmt.Errorf("IPv6 packet too short: %d bytes", len(packet))
	}

	// Extract destination IP from packet header (bytes 24-39)
	dstIP := net.IP(packet[24:40])

	// Create sockaddr
	sa := &unix.SockaddrInet6{
		Port: 0, // Raw socket doesn't use port
	}
	copy(sa.Addr[:], dstIP.To16())

	// Send packet - kernel handles routing, fragmentation, etc.
	err := unix.Sendto(p.fd6, packet, 0, sa)
	if err != nil {
		return fmt.Errorf("failed to send IPv6 packet: %w", err)
	}

	return nil
}

// Close closes the raw sockets
func (p *PacketInjector) Close() error {
	var err error
	if p.fd4 >= 0 {
		if e := unix.Close(p.fd4); e != nil {
			err = e
		}
		p.fd4 = -1
	}
	if p.fd6 >= 0 {
		if e := unix.Close(p.fd6); e != nil {
			err = e
		}
		p.fd6 = -1
	}
	return err
}
