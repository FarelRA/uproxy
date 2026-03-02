package tun

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/songgao/water"
	"golang.org/x/crypto/ssh"

	"uproxy/internal/framing"
)

// TUNManager manages a single TUN device shared by multiple clients.
// It handles packet routing to the correct client.
type TUNManager struct {
	device    *water.Interface
	config    *Config
	outbound  string
	autoRoute bool // Whether to automatically set up NAT/forwarding

	mu        sync.RWMutex
	clients   map[string]*ClientRoute // Map: client IP → routing info
	allocator *IPAllocator            // IP address allocator

	ctx    context.Context
	cancel context.CancelFunc
}

// ClientRoute holds routing information for a single client.
type ClientRoute struct {
	IPv4    string
	IPv6    string
	Channel ssh.Channel
	done    chan struct{}
}

// NewTUNManager creates a TUN manager with a shared TUN device.
func NewTUNManager(cfg *Config, outbound string, autoRoute bool) (*TUNManager, error) {
	// Create TUN device
	device, err := CreateTUN(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %v", err)
	}

	// Conditionally enable IP forwarding and NAT
	if autoRoute {
		// Enable IP forwarding
		if err := EnableIPForwarding(); err != nil {
			device.Close()
			return nil, fmt.Errorf("failed to enable IP forwarding: %v", err)
		}

		// Set up NAT/masquerading with subnet filtering
		// Construct subnet strings for NAT rules
		ipv4Subnet := ""
		if cfg.IP != "" && cfg.Netmask != "" {
			ipv4Subnet = cfg.IP + "/" + cfg.Netmask
		}
		ipv6Subnet := cfg.IPv6 // Already includes /64

		if err := EnableNAT(device.Name(), outbound, ipv4Subnet, ipv6Subnet); err != nil {
			device.Close()
			return nil, fmt.Errorf("failed to setup NAT: %v", err)
		}
	} else {
		slog.Info("Auto-route disabled, skipping NAT/forwarding setup")
	}

	// Create IP allocator
	allocator := NewIPAllocator(cfg.IP, cfg.Netmask, cfg.IPv6)

	ctx, cancel := context.WithCancel(context.Background())
	mgr := &TUNManager{
		device:    device,
		config:    cfg,
		outbound:  outbound,
		autoRoute: autoRoute,
		clients:   make(map[string]*ClientRoute),
		allocator: allocator,
		ctx:       ctx,
		cancel:    cancel,
	}

	// Start packet dispatcher with context
	go mgr.dispatchPackets()

	slog.Info("TUN manager initialized", "device", cfg.Name, "ip", cfg.IP, "ipv6", cfg.IPv6)
	return mgr, nil
}

// AllocateIP assigns IP addresses (IPv4 and optionally IPv6) to a new client
func (m *TUNManager) AllocateIP() (ipv4 string, ipv6 string, err error) {
	return m.allocator.AllocateIP()
}

// AllocateAndNotifyClient allocates IPs, notifies the client, and registers them.
// This is a convenience method that combines AllocateIP, notification, and RegisterClient.
func (m *TUNManager) AllocateAndNotifyClient(channel ssh.Channel) (*ClientRoute, string, string, error) {
	// Allocate IPs for this client
	clientIPv4, clientIPv6, err := m.AllocateIP()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to allocate IP: %w", err)
	}

	slog.Info("IPs allocated for client", "ipv4", clientIPv4, "ipv6", clientIPv6)

	// Send assigned IPs to client
	ipMsg := fmt.Sprintf("IPv4:%s\n", clientIPv4)
	if clientIPv6 != "" {
		ipMsg += fmt.Sprintf("IPv6:%s\n", clientIPv6)
	}
	if _, err := channel.Write([]byte(ipMsg)); err != nil {
		// Release the allocated IPs since we failed to notify
		m.allocator.ReleaseIP(clientIPv4, clientIPv6)
		return nil, "", "", fmt.Errorf("failed to send IPs to client: %w", err)
	}

	// Register client with manager
	route := m.RegisterClient(clientIPv4, clientIPv6, channel)
	return route, clientIPv4, clientIPv6, nil
}

// RegisterClient registers a client with its assigned IPs and channel.
func (m *TUNManager) RegisterClient(ipv4, ipv6 string, channel ssh.Channel) *ClientRoute {
	m.mu.Lock()
	defer m.mu.Unlock()

	route := &ClientRoute{
		IPv4:    ipv4,
		IPv6:    ipv6,
		Channel: channel,
		done:    make(chan struct{}),
	}

	m.clients[ipv4] = route
	if ipv6 != "" {
		// Extract IP without prefix for routing
		if ip, _, err := net.ParseCIDR(ipv6); err == nil {
			m.clients[ip.String()] = route
		}
	}

	slog.Info("Client registered", "ipv4", ipv4, "ipv6", ipv6, "total_clients", len(m.clients))

	return route
}

// UnregisterClient removes a client and frees its IPs back to the pool.
func (m *TUNManager) UnregisterClient(ipv4, ipv6 string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if route, exists := m.clients[ipv4]; exists {
		close(route.done)
		delete(m.clients, ipv4)
		if ipv6 != "" {
			if ip, _, err := net.ParseCIDR(ipv6); err == nil {
				delete(m.clients, ip.String())
			}
		}

		// Release IPs back to allocator
		m.allocator.ReleaseIP(ipv4, ipv6)

		slog.Info("Client unregistered and IPs freed", "ipv4", ipv4, "ipv6", ipv6, "total_clients", len(m.clients))
	}
}

// parsePacketDestination extracts the destination IP from an IP packet
func parsePacketDestination(packet []byte, n int) (string, bool) {
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

// dispatchPackets reads packets from TUN device and routes them to the correct client.
func (m *TUNManager) dispatchPackets() {
	buf := make([]byte, 2048)

	for {
		select {
		case <-m.ctx.Done():
			slog.Info("Packet dispatcher shutting down")
			return
		default:
		}

		n, err := m.device.Read(buf)
		if err != nil {
			select {
			case <-m.ctx.Done():
				return
			default:
				slog.Error("TUN read error", "error", err)
				return
			}
		}

		if n < 20 {
			continue // Too small to be valid IP packet
		}

		packet := buf[:n]

		// Parse destination IP from packet
		dstIP, ok := parsePacketDestination(packet, n)
		if !ok {
			continue
		}

		// Route packet to correct client
		m.mu.RLock()
		route, exists := m.clients[dstIP]
		m.mu.RUnlock()

		if !exists {
			// No client with this IP, drop packet
			continue
		}

		// Send packet to client's SSH channel (framed)
		select {
		case <-route.done:
			// Client disconnected
			continue
		default:
			if err := framing.WriteFramed(route.Channel, packet); err != nil {
				slog.Debug("Failed to write packet to client", "ip", dstIP, "error", err)
			}
		}
	}
}

// WritePacket writes a packet from a client to the TUN device.
func (m *TUNManager) WritePacket(packet []byte) error {
	_, err := m.device.Write(packet)
	return err
}

// Close shuts down the TUN manager and cleans up resources.
// cleanupClients closes all client routes and clears the client map
func (m *TUNManager) cleanupClients() {
	// Close all client routes (avoid double-close for dual-stack clients)
	closed := make(map[*ClientRoute]bool)
	for _, route := range m.clients {
		if !closed[route] {
			close(route.done)
			closed[route] = true
		}
	}
	m.clients = make(map[string]*ClientRoute)
}

// cleanupNAT disables NAT rules if auto-route was enabled
func (m *TUNManager) cleanupNAT() {
	if !m.autoRoute {
		return
	}

	// Construct subnet strings from config
	ipv4Subnet := ""
	if m.config.IP != "" && m.config.Netmask != "" {
		// Parse IP and netmask to get network address
		ip := net.ParseIP(m.config.IP)
		if ip != nil {
			ip = ip.To4()
			if ip != nil && len(ip) >= 3 {
				// Convert netmask to CIDR prefix length
				ipv4Subnet = fmt.Sprintf("%d.%d.%d.0%s", ip[0], ip[1], ip[2], m.config.Netmask)
			}
		}
	}

	ipv6Subnet := ""
	if m.config.IPv6 != "" {
		// IPv6 is already in CIDR format (e.g., "fd42:cafe:beef::1/64")
		// Extract the network prefix
		if ip, ipnet, err := net.ParseCIDR(m.config.IPv6); err == nil {
			// Get the network address (zero out host bits)
			networkIP := ip.Mask(ipnet.Mask)
			ones, _ := ipnet.Mask.Size()
			ipv6Subnet = fmt.Sprintf("%s/%d", networkIP.String(), ones)
		}
	}

	DisableNAT(m.device.Name(), m.outbound, ipv4Subnet, ipv6Subnet)
}

func (m *TUNManager) Close() error {
	// Cancel context to stop dispatcher goroutine
	m.cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupClients()
	m.cleanupNAT()

	// Close TUN device
	return m.device.Close()
}
