package tun

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"sync"

	"github.com/songgao/water"
	"golang.org/x/crypto/ssh"
)

// TUNManager manages a single TUN device shared by multiple clients.
// It handles IP address allocation and packet routing to the correct client.
type TUNManager struct {
	device    *water.Interface
	config    *Config
	outbound  string
	autoRoute bool // Whether to automatically set up NAT/forwarding

	mu       sync.RWMutex
	clients  map[string]*ClientRoute // Map: client IP → routing info
	heldIPv4 map[string]bool         // Currently held IPv4 addresses
	heldIPv6 map[string]bool         // Currently held IPv6 addresses

	// CIDR configuration for on-the-fly IP generation
	ipv4Network net.IP
	ipv4Mask    net.IPMask
	ipv6Network net.IP
	ipv6Prefix  int
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

	// Parse IPv4 CIDR configuration
	ipv4Network, ipv4Mask := parseIPv4Config(cfg.IP, cfg.Netmask)

	// Parse IPv6 CIDR configuration
	var ipv6Network net.IP
	var ipv6Prefix int
	if cfg.IPv6 != "" {
		ipv6Network, ipv6Prefix = parseIPv6Config(cfg.IPv6)
	}

	mgr := &TUNManager{
		device:      device,
		config:      cfg,
		outbound:    outbound,
		autoRoute:   autoRoute,
		clients:     make(map[string]*ClientRoute),
		heldIPv4:    make(map[string]bool),
		heldIPv6:    make(map[string]bool),
		ipv4Network: ipv4Network,
		ipv4Mask:    ipv4Mask,
		ipv6Network: ipv6Network,
		ipv6Prefix:  ipv6Prefix,
	}

	// Start packet dispatcher
	go mgr.dispatchPackets()

	slog.Info("TUN manager initialized", "device", cfg.Name, "ip", cfg.IP, "ipv6", cfg.IPv6)
	return mgr, nil
}

// parseIPv4Config parses IPv4 configuration and returns network address and mask.
func parseIPv4Config(serverIP, netmask string) (net.IP, net.IPMask) {
	ip := net.ParseIP(serverIP)
	if ip == nil {
		return nil, nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil, nil
	}

	mask := net.ParseIP(netmask)
	if mask == nil {
		return nil, nil
	}
	mask = mask.To4()
	if mask == nil {
		return nil, nil
	}

	// Calculate network address
	network := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		network[i] = ip[i] & mask[i]
	}

	return network, net.IPMask(mask)
}

// parseIPv6Config parses IPv6 CIDR and returns network address and prefix length.
func parseIPv6Config(serverIPv6 string) (net.IP, int) {
	ip, ipnet, err := net.ParseCIDR(serverIPv6)
	if err != nil {
		return nil, 0
	}

	if ip.To4() != nil {
		return nil, 0 // Not an IPv6 address
	}

	prefixLen, _ := ipnet.Mask.Size()
	return ipnet.IP, prefixLen
}

// AllocateIP assigns IP addresses (IPv4 and optionally IPv6) to a new client using random generation.
func (m *TUNManager) AllocateIP() (ipv4 string, ipv6 string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate random IPv4
	ipv4, err = m.generateRandomIPv4()
	if err != nil {
		return "", "", fmt.Errorf("failed to allocate IPv4: %v", err)
	}
	m.heldIPv4[ipv4] = true

	// Generate random IPv6 if configured
	if m.ipv6Network != nil {
		ipv6, err = m.generateRandomIPv6()
		if err != nil {
			// IPv6 allocation failed, but IPv4 succeeded - continue with IPv4 only
			slog.Warn("Failed to allocate IPv6", "error", err)
			ipv6 = ""
		} else {
			m.heldIPv6[ipv6] = true
		}
	}

	return ipv4, ipv6, nil
}

// generateRandomIPv4 generates a random IPv4 address within the configured network.
func (m *TUNManager) generateRandomIPv4() (string, error) {
	if m.ipv4Network == nil {
		return "", fmt.Errorf("IPv4 network not configured")
	}

	serverIP := m.config.IP
	maxAttempts := 500 // Prevent infinite loops

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Generate random last octet (2-254, skip .0, .1, .255)
		n, err := rand.Int(rand.Reader, big.NewInt(253))
		if err != nil {
			continue
		}
		lastOctet := byte(n.Int64() + 2) // Range: 2-254

		// Construct IP
		ip := make(net.IP, 4)
		copy(ip, m.ipv4Network)
		ip[3] = lastOctet

		ipStr := ip.String()

		// Skip server IP
		if ipStr == serverIP {
			continue
		}

		// Check if already held
		if !m.heldIPv4[ipStr] {
			return ipStr, nil
		}
	}

	return "", fmt.Errorf("IPv4 pool exhausted or too many collisions")
}

// generateRandomIPv6 generates a random IPv6 address within the configured network.
func (m *TUNManager) generateRandomIPv6() (string, error) {
	if m.ipv6Network == nil {
		return "", fmt.Errorf("IPv6 network not configured")
	}

	serverIP := m.config.IPv6
	maxAttempts := 500

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Generate random last octet (2-254)
		n, err := rand.Int(rand.Reader, big.NewInt(253))
		if err != nil {
			continue
		}
		lastOctet := byte(n.Int64() + 2)

		// Construct IP
		ip := make(net.IP, 16)
		copy(ip, m.ipv6Network)
		ip[15] = lastOctet

		ipStr := fmt.Sprintf("%s/%d", ip.String(), m.ipv6Prefix)

		// Skip server IP
		if ipStr == serverIP {
			continue
		}

		// Check if already held
		if !m.heldIPv6[ipStr] {
			return ipStr, nil
		}
	}

	return "", fmt.Errorf("IPv6 pool exhausted or too many collisions")
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

		// Free the held IPs
		delete(m.heldIPv4, ipv4)
		if ipv6 != "" {
			delete(m.heldIPv6, ipv6)
		}

		slog.Info("Client unregistered and IPs freed", "ipv4", ipv4, "ipv6", ipv6, "total_clients", len(m.clients))
	}
}

// dispatchPackets reads packets from TUN device and routes them to the correct client.
func (m *TUNManager) dispatchPackets() {
	buf := make([]byte, 2048)

	for {
		n, err := m.device.Read(buf)
		if err != nil {
			slog.Error("TUN read error", "error", err)
			return
		}

		if n < 20 {
			continue // Too small to be valid IP packet
		}

		packet := buf[:n]

		// Parse IP header to get destination
		version := packet[0] >> 4
		var dstIP string

		if version == 4 {
			if n < 20 {
				continue
			}
			dstIP = net.IP(packet[16:20]).String()
		} else if version == 6 {
			if n < 40 {
				continue
			}
			dstIP = net.IP(packet[24:40]).String()
		} else {
			continue // Invalid IP version
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
			if err := writeFramed(route.Channel, packet); err != nil {
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
func (m *TUNManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Close all client routes (avoid double-close for dual-stack clients)
	closed := make(map[*ClientRoute]bool)
	for _, route := range m.clients {
		if !closed[route] {
			close(route.done)
			closed[route] = true
		}
	}
	m.clients = make(map[string]*ClientRoute)

	// Cleanup NAT - construct subnet strings from config
	ipv4Subnet := ""
	if m.config.IP != "" && m.config.Netmask != "" {
		// Parse IP and netmask to get network address
		ip := net.ParseIP(m.config.IP)
		if ip != nil {
			ip = ip.To4()
			if ip != nil {
				// Convert netmask to CIDR prefix length
				ipv4Subnet = fmt.Sprintf("%s.%s.%s.0%s", ip[0:1], ip[1:2], ip[2:3], m.config.Netmask)
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

	// Conditionally cleanup NAT if auto-route was enabled
	if m.autoRoute {
		DisableNAT(m.device.Name(), m.outbound, ipv4Subnet, ipv6Subnet)
	}

	// Close TUN device
	return m.device.Close()
}
