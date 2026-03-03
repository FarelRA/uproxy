package tun

import (
	"context"
	"log/slog"
	"net"
	"time"

	"uproxy/internal/framing"
)

// PacketRouter handles packet dispatch from the TUN device to clients.
type PacketRouter struct {
	deviceMgr      *DeviceManager
	clientRegistry *ClientRegistry
	ctx            context.Context
}

// NewPacketRouter creates a new packet router.
func NewPacketRouter(deviceMgr *DeviceManager, clientRegistry *ClientRegistry, ctx context.Context) *PacketRouter {
	return &PacketRouter{
		deviceMgr:      deviceMgr,
		clientRegistry: clientRegistry,
		ctx:            ctx,
	}
}

// Start begins the packet dispatch loop.
func (pr *PacketRouter) Start() {
	go pr.dispatchPackets()
}

// dispatchPackets reads packets from TUN device and routes them to the correct client.
func (pr *PacketRouter) dispatchPackets() {
	buf := make([]byte, MaxPacketSize)

	for {
		select {
		case <-pr.ctx.Done():
			slog.Info("Packet dispatcher shutting down")
			return
		default:
		}

		n, err := pr.deviceMgr.Read(buf)
		if err != nil {
			select {
			case <-pr.ctx.Done():
				return
			default:
				slog.Error("TUN read error, retrying", "error", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		if n < 20 {
			continue // Too small to be valid IP packet
		}

		packet := buf[:n]

		// Parse destination IP from packet
		dstIP, ok := pr.parsePacketDestination(packet, n)
		if !ok {
			continue
		}

		// Route packet to correct client
		pr.routePacketToClient(packet, dstIP)
	}
}

// parsePacketDestination extracts the destination IP from an IP packet.
func (pr *PacketRouter) parsePacketDestination(packet []byte, n int) (string, bool) {
	version := packet[0] >> 4

	if version == 4 {
		if n < 20 {
			return "", false
		}
		return net.IP(packet[16:20]).String(), true
	} else if version == 6 {
		if n < 40 {
			return "", false
		}
		return net.IP(packet[24:40]).String(), true
	}

	return "", false // Invalid IP version
}

// routePacketToClient routes a packet to the appropriate client based on destination IP.
func (pr *PacketRouter) routePacketToClient(packet []byte, dstIP string) {
	route, exists := pr.clientRegistry.GetClient(dstIP)
	if !exists {
		// No client with this IP, drop packet
		return
	}

	// Send packet to client's SSH channel (framed) with quick retry
	select {
	case <-route.done:
		// Client disconnected
		return
	default:
		const maxRetries = 3
		var lastErr error
		for retry := 0; retry < maxRetries; retry++ {
			if err := framing.WriteFramed(route.Channel, packet); err != nil {
				lastErr = err
				// Quick retry without sleep to avoid blocking dispatch loop
				continue
			} else {
				lastErr = nil
				break
			}
		}
		if lastErr != nil {
			slog.Warn("Failed to write packet to client after retries", "ip", dstIP, "retries", maxRetries, "error", lastErr)
		}
	}
}
