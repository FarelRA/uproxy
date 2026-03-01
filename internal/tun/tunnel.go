package tun

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

const (
	ChannelTypeTUN = "tun-ip"
	MaxPacketSize  = 2000 // Maximum IP packet size we'll handle
)

// ServeTUN starts the TUN tunnel, reading packets from the TUN device and forwarding them through SSH
func ServeTUN(ctx context.Context, sshClient *ssh.Client, cfg *Config, routes string) error {
	// Create and configure TUN device
	iface, err := CreateTUN(cfg)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	defer iface.Close()

	// Add routes if specified
	routeList := ParseRoutes(routes)
	for _, route := range routeList {
		if err := AddRoute(route, iface.Name()); err != nil {
			slog.Warn("Failed to add route", "route", route, "error", err)
		}
	}

	slog.Info("TUN tunnel started", "device", iface.Name(), "ip", cfg.IP)

	// Statistics
	var txPackets, rxPackets, txBytes, rxBytes atomic.Int64

	// Channel for SSH channel
	sshChan, err := openTUNChannel(sshClient)
	if err != nil {
		return fmt.Errorf("failed to open SSH channel: %w", err)
	}
	defer sshChan.Close()

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// TUN -> SSH (TX)
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, MaxPacketSize)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, err := iface.Read(buf)
			if err != nil {
				errChan <- fmt.Errorf("TUN read error: %w", err)
				return
			}

			if n == 0 {
				continue
			}

			packet := buf[:n]

			// Log packet info (debug)
			if version := IPVersion(packet); version == 4 {
				if src, dst, proto, err := ParseIPv4Header(packet); err == nil {
					slog.Debug("TX packet", "src", src, "dst", dst, "proto", ProtocolName(proto), "size", n)
				}
			}

			// Write framed packet to SSH channel
			if err := writeFramed(sshChan, packet); err != nil {
				errChan <- fmt.Errorf("SSH write error: %w", err)
				return
			}

			txPackets.Add(1)
			txBytes.Add(int64(n))
		}
	}()

	// SSH -> TUN (RX)
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Read framed packet from SSH channel
			packet, err := readFramed(sshChan)
			if err != nil {
				if err != io.EOF {
					errChan <- fmt.Errorf("SSH read error: %w", err)
				}
				return
			}

			// Log packet info (debug)
			if version := IPVersion(packet); version == 4 {
				if src, dst, proto, err := ParseIPv4Header(packet); err == nil {
					slog.Debug("RX packet", "src", src, "dst", dst, "proto", ProtocolName(proto), "size", len(packet))
				}
			}

			// Write packet to TUN device
			if _, err := iface.Write(packet); err != nil {
				errChan <- fmt.Errorf("TUN write error: %w", err)
				return
			}

			rxPackets.Add(1)
			rxBytes.Add(int64(len(packet)))
		}
	}()

	// Wait for error or context cancellation
	select {
	case err := <-errChan:
		slog.Info("TUN tunnel stats", "tx_packets", txPackets.Load(), "rx_packets", rxPackets.Load(),
			"tx_bytes", txBytes.Load(), "rx_bytes", rxBytes.Load())
		return err
	case <-ctx.Done():
		slog.Info("TUN tunnel stats", "tx_packets", txPackets.Load(), "rx_packets", rxPackets.Load(),
			"tx_bytes", txBytes.Load(), "rx_bytes", rxBytes.Load())
		return ctx.Err()
	}
}

// openTUNChannel opens an SSH channel for TUN traffic
func openTUNChannel(client *ssh.Client) (ssh.Channel, error) {
	channel, reqs, err := client.OpenChannel(ChannelTypeTUN, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open channel: %w", err)
	}

	// Discard requests
	go ssh.DiscardRequests(reqs)

	return channel, nil
}

// writeFramed writes a length-prefixed packet to the channel
func writeFramed(w io.Writer, data []byte) error {
	if len(data) > 65535 {
		return fmt.Errorf("packet too large: %d bytes", len(data))
	}

	// Write 2-byte length prefix
	length := uint16(len(data))
	lengthBuf := []byte{byte(length >> 8), byte(length)}

	if _, err := w.Write(lengthBuf); err != nil {
		return err
	}

	// Write data
	if _, err := w.Write(data); err != nil {
		return err
	}

	return nil
}

// readFramed reads a length-prefixed packet from the channel
func readFramed(r io.Reader) ([]byte, error) {
	// Read 2-byte length prefix
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lengthBuf); err != nil {
		return nil, err
	}

	length := uint16(lengthBuf[0])<<8 | uint16(lengthBuf[1])
	if length == 0 {
		return nil, fmt.Errorf("invalid packet length: 0")
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	return data, nil
}

// HandleTUN handles TUN packets on the server side
func HandleTUN(channel ssh.Channel) {
	defer channel.Close()

	slog.Info("TUN channel opened")

	var txPackets, rxPackets, txBytes, rxBytes atomic.Int64

	var wg sync.WaitGroup

	// Read from channel, forward to network
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			packet, err := readFramed(channel)
			if err != nil {
				if err != io.EOF {
					slog.Error("Failed to read from channel", "error", err)
				}
				return
			}

			rxPackets.Add(1)
			rxBytes.Add(int64(len(packet)))

			// Parse and route packet
			if err := routePacket(packet, channel); err != nil {
				slog.Error("Failed to route packet", "error", err)
			}
		}
	}()

	wg.Wait()
	slog.Info("TUN channel closed", "tx_packets", txPackets.Load(), "rx_packets", rxPackets.Load(),
		"tx_bytes", txBytes.Load(), "rx_bytes", rxBytes.Load())
}

// routePacket routes an IP packet to its destination and sends the response back
func routePacket(packet []byte, channel ssh.Channel) error {
	version := IPVersion(packet)

	switch version {
	case 4:
		return routeIPv4Packet(packet, channel)
	case 6:
		return routeIPv6Packet(packet, channel)
	default:
		return fmt.Errorf("unsupported IP version: %d", version)
	}
}

// routeIPv4Packet routes an IPv4 packet
func routeIPv4Packet(packet []byte, channel ssh.Channel) error {
	src, dst, proto, err := ParseIPv4Header(packet)
	if err != nil {
		return err
	}

	slog.Debug("Routing IPv4 packet", "src", src, "dst", dst, "proto", ProtocolName(proto), "size", len(packet))

	// TODO: Implement actual packet routing
	// For now, this is a placeholder that would need:
	// 1. Raw socket creation
	// 2. Packet injection into the network stack
	// 3. Response capture and forwarding back through the channel

	// This requires CAP_NET_RAW capability and is complex
	// A simpler approach would be to use a userspace TCP/IP stack like gvisor/netstack

	return fmt.Errorf("packet routing not yet implemented")
}

// routeIPv6Packet routes an IPv6 packet
func routeIPv6Packet(packet []byte, channel ssh.Channel) error {
	src, dst, proto, err := ParseIPv6Header(packet)
	if err != nil {
		return err
	}

	slog.Debug("Routing IPv6 packet", "src", src, "dst", dst, "proto", ProtocolName(proto), "size", len(packet))

	// TODO: Implement IPv6 packet routing
	return fmt.Errorf("IPv6 packet routing not yet implemented")
}
