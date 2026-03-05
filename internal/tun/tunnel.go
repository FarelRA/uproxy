package tun

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/songgao/water"
	"uproxy/internal/framing"
	"uproxy/internal/quictransport"
)

const (
	ChannelTypeTUN = "tun-ip"
	MaxPacketSize  = 2000 // Maximum IP packet size we'll handle

	// IP assignment protocol prefixes
	IPAssignmentErrorPrefix = "ERROR:"
	IPAssignmentIPv4Prefix  = "IPv4:"
	IPAssignmentIPv6Prefix  = "IPv6:"
)

// ServeTUN starts the TUN tunnel, reading packets from the TUN device and forwarding them through QUIC
func ServeTUN(ctx context.Context, quicClient *quictransport.Client, cfg *Config, routes string, autoRoute bool, serverAddr string) error {
	// Setup TUN device and routing
	stream, iface, routeMonitor, err := setupTUNDevice(ctx, quicClient, cfg, routes, autoRoute, serverAddr)
	if err != nil {
		return err
	}
	defer stream.Close()
	defer iface.Close()
	if routeMonitor != nil {
		defer routeMonitor.Stop()
	}

	slog.Info("TUN tunnel started", "device", iface.Name(), "ip", cfg.IP)

	// Start bidirectional forwarding
	return runTUNForwarding(ctx, stream, iface)
}

// setupTUNDevice creates and configures the TUN device with server-assigned IPs and routing
func setupTUNDevice(ctx context.Context, quicClient *quictransport.Client, cfg *Config, routes string, autoRoute bool, serverAddr string) (net.Conn, *water.Interface, *RouteMonitor, error) {
	// Open QUIC stream first to receive server-assigned IPs
	stream, err := openTUNStream(ctx, quicClient)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open QUIC stream: %w", err)
	}

	// Read server-assigned IPs
	assignedIPv4, assignedIPv6, err := readServerAssignedIPs(stream)
	if err != nil {
		stream.Close()
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
		stream.Close()
		return nil, nil, nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	// Set up routing
	routeMonitor, err := setupTUNRouting(iface.Name(), routes, autoRoute, serverAddr)
	if err != nil {
		iface.Close()
		stream.Close()
		return nil, nil, nil, err
	}

	return stream, iface, routeMonitor, nil
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

// runTUNForwarding runs bidirectional packet forwarding between TUN device and QUIC stream
func runTUNForwarding(ctx context.Context, stream net.Conn, iface *water.Interface) error {
	var txPackets, rxPackets, txBytes, rxBytes atomic.Int64

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// TUN -> QUIC (TX)
	wg.Add(1)
	go func() {
		defer wg.Done()
		forwardTUNToQUIC(ctx, iface, stream, &txPackets, &txBytes, errChan)
	}()

	// QUIC -> TUN (RX)
	wg.Add(1)
	go func() {
		defer wg.Done()
		forwardQUICToTUN(ctx, stream, iface, &rxPackets, &rxBytes, errChan)
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

// forwardTUNToQUIC forwards packets from TUN device to QUIC stream
func forwardTUNToQUIC(ctx context.Context, iface *water.Interface, stream net.Conn, txPackets, txBytes *atomic.Int64, errChan chan<- error) {
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
			slog.Warn("Dropping invalid packet from TUN device", "size", n)
			continue
		}

		// Write framed packet to QUIC stream with retry
		const maxRetries = 3
		var lastErr error
		for retry := 0; retry < maxRetries; retry++ {
			if err := framing.WriteFramed(stream, packet); err != nil {
				lastErr = err
				if retry < maxRetries-1 {
					// Check context before retrying
					select {
					case <-ctx.Done():
						return
					default:
						time.Sleep(time.Duration(retry+1) * 10 * time.Millisecond)
						continue
					}
				}
			} else {
				lastErr = nil
				break
			}
		}
		if lastErr != nil {
			errChan <- fmt.Errorf("QUIC write error after %d retries: %w", maxRetries, lastErr)
			return
		}

		txPackets.Add(1)
		txBytes.Add(int64(n))
	}
}

// forwardQUICToTUN forwards packets from QUIC stream to TUN device
func forwardQUICToTUN(ctx context.Context, stream net.Conn, iface *water.Interface, rxPackets, rxBytes *atomic.Int64, errChan chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Read framed packet from QUIC stream
		packet, err := framing.ReadFramed(stream)
		if err != nil {
			if err != io.EOF {
				errChan <- fmt.Errorf("QUIC read error: %w", err)
			}
			return
		}

		// Basic validation
		if !ValidatePacket(packet) {
			slog.Warn("Dropping invalid packet from QUIC stream", "size", len(packet))
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
func readServerAssignedIPs(conn net.Conn) (ipv4 string, ipv6 string, err error) {
	// Read framed IP assignment message from server.
	// Format payload: "IPv4:x.x.x.x\n" or "IPv4:x.x.x.x\nIPv6:xxxx::x\n"
	payload, err := framing.ReadFramed(conn)
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

// openTUNStream opens a QUIC stream for TUN traffic
func openTUNStream(ctx context.Context, client *quictransport.Client) (net.Conn, error) {
	stream, err := client.OpenTUNStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open TUN stream: %w", err)
	}

	return stream, nil
}

// HandleTUN handles TUN packets on the server side using the shared TUN manager
func HandleTUN(stream net.Conn, manager *TUNManager) {
	defer stream.Close()

	// Allocate IPs, notify client, and register
	route, clientIPv4, clientIPv6, err := manager.AllocateAndNotifyClient(stream)
	if err != nil {
		slog.Error("Failed to setup client", "error", err)
		if writeErr := framing.WriteFramed(stream, []byte(fmt.Sprintf("ERROR: %v\n", err))); writeErr != nil {
			slog.Debug("Failed to write TUN setup error to stream", "error", writeErr)
		}
		return
	}
	defer manager.UnregisterClient(clientIPv4, clientIPv6)

	slog.Info("TUN stream opened", "client_ipv4", clientIPv4, "client_ipv6", clientIPv6)

	// Statistics
	var txPackets, rxPackets, txBytes, rxBytes atomic.Int64

	// QUIC -> TUN (RX from client)
	// Read packets from client and write to shared TUN device
	for {
		select {
		case <-route.done:
			slog.Info("TUN stream closed", "client_ipv4", clientIPv4, "client_ipv6", clientIPv6,
				"tx_packets", txPackets.Load(), "rx_packets", rxPackets.Load(),
				"tx_bytes", txBytes.Load(), "rx_bytes", rxBytes.Load())
			return
		default:
		}

		packet, err := framing.ReadFramed(stream)
		if err != nil {
			if err != io.EOF {
				slog.Debug("QUIC read error", "client_ipv4", clientIPv4, "error", err)
			}
			slog.Info("TUN stream closed", "client_ipv4", clientIPv4, "client_ipv6", clientIPv6,
				"tx_packets", txPackets.Load(), "rx_packets", rxPackets.Load(),
				"tx_bytes", txBytes.Load(), "rx_bytes", rxBytes.Load())
			return
		}

		// Basic validation
		if !ValidatePacket(packet) {
			slog.Warn("Dropping invalid packet from QUIC stream", "client_ipv4", clientIPv4, "size", len(packet))
			continue
		}

		// Write packet to shared TUN device - kernel routes it to internet
		// Retry with exponential backoff for transient errors
		const maxRetries = 3
		var lastErr error
		for attempt := 0; attempt < maxRetries; attempt++ {
			if err := manager.WritePacket(packet); err != nil {
				lastErr = err
				if attempt < maxRetries-1 {
					time.Sleep(time.Duration(10*(attempt+1)) * time.Millisecond)
					continue
				}
			} else {
				lastErr = nil
				break
			}
		}
		if lastErr != nil {
			slog.Warn("TUN write error after retries", "client_ipv4", clientIPv4, "error", lastErr)
			continue
		}

		rxPackets.Add(1)
		rxBytes.Add(int64(len(packet)))
	}

	// Note: TX (TUN -> QUIC) is handled by TUNManager.dispatchPackets()
	// which routes packets to the correct client based on destination IP
}
