package tun

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/songgao/water"
	"golang.org/x/crypto/ssh"
)

// TUNManager manages a single TUN device shared by multiple clients.
// It handles IP address allocation and packet routing to the correct client.
type TUNManager struct {
	device   *water.Interface
	config   *Config
	outbound string

	mu            sync.RWMutex
	clients       map[string]*ClientRoute // Map: client IP → routing info
	ipv4Pool      []string                // Available IPv4 addresses
	ipv6Pool      []string                // Available IPv6 addresses
	nextIPv4Index int
	nextIPv6Index int
}

// ClientRoute holds routing information for a single client.
type ClientRoute struct {
	IPv4    string
	IPv6    string
	Channel ssh.Channel
	done    chan struct{}
}

// NewTUNManager creates a TUN manager with a shared TUN device.
func NewTUNManager(cfg *Config, outbound string) (*TUNManager, error) {
	// Create TUN device
	device, err := CreateTUN(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %v", err)
	}

	// Enable IP forwarding
	if err := EnableIPForwarding(); err != nil {
		device.Close()
		return nil, fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	// Set up NAT/masquerading
	if err := EnableNAT(device.Name(), outbound); err != nil {
		device.Close()
		return nil, fmt.Errorf("failed to setup NAT: %v", err)
	}

	// Generate IP pools
	ipv4Pool := generateIPv4Pool(cfg.IP, cfg.Netmask)
	var ipv6Pool []string
	if cfg.IPv6 != "" {
		ipv6Pool = generateIPv6Pool(cfg.IPv6)
	}

	mgr := &TUNManager{
		device:        device,
		config:        cfg,
		outbound:      outbound,
		clients:       make(map[string]*ClientRoute),
		ipv4Pool:      ipv4Pool,
		ipv6Pool:      ipv6Pool,
		nextIPv4Index: 0,
		nextIPv6Index: 0,
	}

	// Start packet dispatcher
	go mgr.dispatchPackets()

	slog.Info("TUN manager initialized", "device", cfg.Name, "ip", cfg.IP, "ipv4_pool_size", len(ipv4Pool), "ipv6_pool_size", len(ipv6Pool))
	return mgr, nil
}

// generateIPv4Pool creates a list of available client IPv4 addresses.
func generateIPv4Pool(serverIP, netmask string) []string {
	// Parse server IP
	ip := net.ParseIP(serverIP)
	if ip == nil {
		return nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil
	}

	// Parse netmask
	mask := net.ParseIP(netmask)
	if mask == nil {
		return nil
	}
	mask = mask.To4()
	if mask == nil {
		return nil
	}

	// Calculate network address
	network := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		network[i] = ip[i] & mask[i]
	}

	// Generate IPs (skip .0, .1, and .255)
	var pool []string
	for i := 2; i < 255; i++ {
		clientIP := make(net.IP, 4)
		copy(clientIP, network)
		clientIP[3] = byte(i)

		// Skip server IP
		if clientIP.Equal(ip) {
			continue
		}

		pool = append(pool, clientIP.String())
	}

	return pool
}

// generateIPv6Pool creates a list of available client IPv6 addresses.
// Takes an IPv6 CIDR (e.g., "fd00::1/64") and generates addresses from ::2 onwards.
func generateIPv6Pool(serverIPv6 string) []string {
	// Parse IPv6 CIDR
	ip, ipnet, err := net.ParseCIDR(serverIPv6)
	if err != nil {
		return nil
	}

	if ip.To4() != nil {
		return nil // Not an IPv6 address
	}

	// Get the network prefix
	network := ipnet.IP
	prefixLen, _ := ipnet.Mask.Size()

	// For simplicity, generate addresses in the lower 16 bits (last 2 bytes)
	// This works well for /64 networks which are standard
	var pool []string

	// Generate 253 addresses (::2 to ::254)
	for i := 2; i < 255; i++ {
		clientIP := make(net.IP, 16)
		copy(clientIP, network)
		clientIP[15] = byte(i)

		// Skip server IP
		if clientIP.Equal(ip) {
			continue
		}

		pool = append(pool, fmt.Sprintf("%s/%d", clientIP.String(), prefixLen))
	}

	return pool
}

// AllocateIP assigns IP addresses (IPv4 and optionally IPv6) to a new client.
func (m *TUNManager) AllocateIP() (ipv4 string, ipv6 string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.nextIPv4Index >= len(m.ipv4Pool) {
		return "", "", fmt.Errorf("IPv4 pool exhausted")
	}

	ipv4 = m.ipv4Pool[m.nextIPv4Index]
	m.nextIPv4Index++

	// Allocate IPv6 if available
	if len(m.ipv6Pool) > 0 && m.nextIPv6Index < len(m.ipv6Pool) {
		ipv6 = m.ipv6Pool[m.nextIPv6Index]
		m.nextIPv6Index++
	}

	return ipv4, ipv6, nil
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

// UnregisterClient removes a client and frees its IPs.
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
		slog.Info("Client unregistered", "ipv4", ipv4, "ipv6", ipv6, "total_clients", len(m.clients))
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

		// Send packet to client's SSH channel
		select {
		case <-route.done:
			// Client disconnected
			continue
		default:
			_, err := route.Channel.Write(packet)
			if err != nil {
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

	// Close all client routes
	for _, route := range m.clients {
		close(route.done)
	}
	m.clients = make(map[string]*ClientRoute)

	// Cleanup NAT
	DisableNAT(m.device.Name(), m.outbound)

	// Close TUN device
	return m.device.Close()
}
