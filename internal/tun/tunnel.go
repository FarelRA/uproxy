package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/songgao/water"
	"golang.org/x/crypto/ssh"
	"uproxy/internal/framing"
	"uproxy/internal/uproxy"
)

const (
	ChannelTypeTUN = "tun-ip"
	MaxPacketSize  = 2000 // Maximum IP packet size we'll handle

	// IP assignment protocol prefixes
	IPAssignmentErrorPrefix = "ERROR:"
	IPAssignmentIPv4Prefix  = "IPv4:"
	IPAssignmentIPv6Prefix  = "IPv6:"
)

// ServeTUN starts the TUN tunnel, reading packets from the TUN device and forwarding them through SSH
func ServeTUN(ctx context.Context, sshClient *ssh.Client, cfg *Config, routes string, autoRoute bool, serverAddr string) error {
	// Setup TUN device and routing
	sshChan, iface, routeMonitor, err := setupTUNDevice(sshClient, cfg, routes, autoRoute, serverAddr)
	if err != nil {
		return err
	}
	defer sshChan.Close()
	defer iface.Close()
	if routeMonitor != nil {
		defer routeMonitor.Stop()
	}

	slog.Info("TUN tunnel started", "device", iface.Name(), "ip", cfg.IP)

	// Start bidirectional forwarding
	return runTUNForwarding(ctx, sshChan, iface)
}

// setupTUNDevice creates and configures the TUN device with server-assigned IPs and routing
func setupTUNDevice(sshClient *ssh.Client, cfg *Config, routes string, autoRoute bool, serverAddr string) (ssh.Channel, *water.Interface, *RouteMonitor, error) {
	// Open SSH channel first to receive server-assigned IPs
	sshChan, err := openTUNChannel(sshClient)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open SSH channel: %w", err)
	}

	// Read server-assigned IPs
	assignedIPv4, assignedIPv6, err := readServerAssignedIPs(sshChan)
	if err != nil {
		sshChan.Close()
		return nil, nil, nil, fmt.Errorf("failed to read server-assigned IPs: %w", err)
	}

	// Update config with server-assigned IPs
	cfg.IP = assignedIPv4
	if assignedIPv6 != "" {
		cfg.IPv6 = assignedIPv6 // Server already sends with /64 prefix
	}

	slog.Info("Received server-assigned IPs", "ipv4", assignedIPv4, "ipv6", assignedIPv6)

	// Create and configure TUN device with server-assigned IPs
	iface, err := CreateTUN(cfg)
	if err != nil {
		sshChan.Close()
		return nil, nil, nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	// Set up routing
	routeMonitor, err := setupTUNRouting(iface.Name(), routes, autoRoute, serverAddr)
	if err != nil {
		iface.Close()
		sshChan.Close()
		return nil, nil, nil, err
	}

	return sshChan, iface, routeMonitor, nil
}

// setupTUNRouting configures automatic routing and custom routes
func setupTUNRouting(ifaceName, routes string, autoRoute bool, serverAddr string) (*RouteMonitor, error) {
	var routeMonitor *RouteMonitor
	if autoRoute {
		routeMonitor = NewRouteMonitor(serverAddr, ifaceName)
		if err := routeMonitor.Start(); err != nil {
			return nil, fmt.Errorf("failed to set up client routes: %w", err)
		}
	}

	// Add routes if specified
	routeList := ParseRoutes(routes)
	for _, route := range routeList {
		if err := AddRoute(route, ifaceName); err != nil {
			slog.Warn("Failed to add route", "route", route, "error", err)
		}
	}

	return routeMonitor, nil
}

// runTUNForwarding runs bidirectional packet forwarding between TUN device and SSH channel
func runTUNForwarding(ctx context.Context, sshChan ssh.Channel, iface *water.Interface) error {
	var txPackets, rxPackets, txBytes, rxBytes atomic.Int64

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// TUN -> SSH (TX)
	wg.Add(1)
	go func() {
		defer wg.Done()
		forwardTUNToSSH(ctx, iface, sshChan, &txPackets, &txBytes, errChan)
	}()

	// SSH -> TUN (RX)
	wg.Add(1)
	go func() {
		defer wg.Done()
		forwardSSHToTUN(ctx, sshChan, iface, &rxPackets, &rxBytes, errChan)
	}()

	// Wait for error or context cancellation
	select {
	case err := <-errChan:
		logTUNStats(&txPackets, &rxPackets, &txBytes, &rxBytes)
		return err
	case <-ctx.Done():
		logTUNStats(&txPackets, &rxPackets, &txBytes, &rxBytes)
		return ctx.Err()
	}
}

// forwardTUNToSSH forwards packets from TUN device to SSH channel
func forwardTUNToSSH(ctx context.Context, iface *water.Interface, sshChan ssh.Channel, txPackets, txBytes *atomic.Int64, errChan chan<- error) {
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
		if err := framing.WriteFramed(sshChan, packet); err != nil {
			errChan <- fmt.Errorf("SSH write error: %w", err)
			return
		}

		txPackets.Add(1)
		txBytes.Add(int64(n))
	}
}

// forwardSSHToTUN forwards packets from SSH channel to TUN device
func forwardSSHToTUN(ctx context.Context, sshChan ssh.Channel, iface *water.Interface, rxPackets, rxBytes *atomic.Int64, errChan chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read framed packet from SSH channel
		packet, err := framing.ReadFramed(sshChan)
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
}

// logTUNStats logs TUN tunnel statistics
func logTUNStats(txPackets, rxPackets, txBytes, rxBytes *atomic.Int64) {
	slog.Info("TUN tunnel stats",
		"tx_packets", txPackets.Load(),
		"rx_packets", rxPackets.Load(),
		"tx_bytes", txBytes.Load(),
		"rx_bytes", rxBytes.Load())
}

// ErrTUNNotSupported indicates the server doesn't support TUN mode
var ErrTUNNotSupported = fmt.Errorf("server does not support TUN mode")

// readServerAssignedIPs reads the IP addresses assigned by the server
func readServerAssignedIPs(channel ssh.Channel) (ipv4 string, ipv6 string, err error) {
	// Read framed IP assignment message from server.
	// Format payload: "IPv4:x.x.x.x\n" or "IPv4:x.x.x.x\nIPv6:xxxx::x\n"
	payload, err := framing.ReadFramed(channel)
	if err != nil {
		return "", "", fmt.Errorf("failed to read IP assignment: %w", err)
	}

	msg := string(payload)

	// Check for error message
	if strings.HasPrefix(msg, IPAssignmentErrorPrefix) {
		return "", "", fmt.Errorf("server error: %s", strings.TrimSpace(msg[len(IPAssignmentErrorPrefix):]))
	}

	// Parse IP assignment
	lines := strings.Split(strings.TrimSpace(msg), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, IPAssignmentIPv4Prefix) {
			ipv4 = strings.TrimSpace(line[len(IPAssignmentIPv4Prefix):])
		} else if strings.HasPrefix(line, IPAssignmentIPv6Prefix) {
			ipv6 = strings.TrimSpace(line[len(IPAssignmentIPv6Prefix):])
		}
	}

	if ipv4 == "" {
		return "", "", fmt.Errorf("server did not assign IPv4 address")
	}

	return ipv4, ipv6, nil
}

// openTUNChannel opens an SSH channel for TUN traffic
func openTUNChannel(client *ssh.Client) (ssh.Channel, error) {
	channel, err := uproxy.OpenSSHChannel(client, ChannelTypeTUN)
	if err != nil {
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) && openErr.Reason == ssh.UnknownChannelType {
			return nil, ErrTUNNotSupported
		}
		return nil, err
	}

	return channel, nil
}

// HandleTUN handles TUN packets on the server side using the shared TUN manager
func HandleTUN(channel ssh.Channel, manager *TUNManager) {
	defer channel.Close()

	// Allocate IPs, notify client, and register
	route, clientIPv4, clientIPv6, err := manager.AllocateAndNotifyClient(channel)
	if err != nil {
		slog.Error("Failed to setup client", "error", err)
		if writeErr := framing.WriteFramed(channel, []byte(fmt.Sprintf("ERROR: %v\n", err))); writeErr != nil {
			slog.Debug("Failed to write TUN setup error to channel", "error", writeErr)
		}
		return
	}
	defer manager.UnregisterClient(clientIPv4, clientIPv6)

	slog.Info("TUN channel opened", "client_ipv4", clientIPv4, "client_ipv6", clientIPv6)

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

		packet, err := framing.ReadFramed(channel)
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
