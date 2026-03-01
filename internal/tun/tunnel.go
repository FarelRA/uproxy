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

			// Basic validation
			if !ValidatePacket(packet) {
				slog.Debug("Invalid packet dropped", "size", n)
				continue
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

			// Basic validation
			if !ValidatePacket(packet) {
				slog.Debug("Invalid packet dropped", "size", len(packet))
				continue
			}

			// Write packet to TUN device - kernel handles the rest
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

// HandleTUN handles TUN packets on the server side using the shared TUN manager
func HandleTUN(channel ssh.Channel, manager *TUNManager) {
	defer channel.Close()

	// Allocate IPs for this client (IPv4 and optionally IPv6)
	clientIPv4, clientIPv6, err := manager.AllocateIP()
	if err != nil {
		slog.Error("Failed to allocate IP for client", "error", err)
		channel.Write([]byte("ERROR: No available IPs\n"))
		return
	}

	slog.Info("TUN channel opened", "client_ipv4", clientIPv4, "client_ipv6", clientIPv6)

	// Send assigned IPs to client
	ipMsg := fmt.Sprintf("IPv4:%s\n", clientIPv4)
	if clientIPv6 != "" {
		ipMsg += fmt.Sprintf("IPv6:%s\n", clientIPv6)
	}
	if _, err := channel.Write([]byte(ipMsg)); err != nil {
		slog.Error("Failed to send IPs to client", "error", err)
		return
	}

	// Register client with manager
	route := manager.RegisterClient(clientIPv4, clientIPv6, channel)
	defer manager.UnregisterClient(clientIPv4, clientIPv6)

	// Statistics
	var txPackets, rxPackets, txBytes, rxBytes atomic.Int64

	// SSH -> TUN (RX from client)
	// Read packets from client and write to shared TUN device
	for {
		select {
		case <-route.done:
			slog.Info("TUN channel closed", "client_ipv4", clientIPv4, "client_ipv6", clientIPv6,
				"tx_packets", txPackets.Load(), "rx_packets", rxPackets.Load(),
				"tx_bytes", txBytes.Load(), "rx_bytes", rxBytes.Load())
			return
		default:
		}

		packet, err := readFramed(channel)
		if err != nil {
			if err != io.EOF {
				slog.Debug("SSH read error", "client_ipv4", clientIPv4, "error", err)
			}
			slog.Info("TUN channel closed", "client_ipv4", clientIPv4, "client_ipv6", clientIPv6,
				"tx_packets", txPackets.Load(), "rx_packets", rxPackets.Load(),
				"tx_bytes", txBytes.Load(), "rx_bytes", rxBytes.Load())
			return
		}

		// Basic validation
		if !ValidatePacket(packet) {
			slog.Debug("Invalid packet dropped", "client_ipv4", clientIPv4, "size", len(packet))
			continue
		}

		// Write packet to shared TUN device - kernel routes it to internet
		if err := manager.WritePacket(packet); err != nil {
			slog.Debug("TUN write error", "client_ipv4", clientIPv4, "error", err)
			continue
		}

		rxPackets.Add(1)
		rxBytes.Add(int64(len(packet)))
	}

	// Note: TX (TUN -> SSH) is handled by TUNManager.dispatchPackets()
	// which routes packets to the correct client based on destination IP
}
