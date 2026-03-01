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

	mu          sync.RWMutex
	clients     map[string]*ClientRoute // Map: client IP → routing info
	ipPool      []string                // Available IPs
	nextIPIndex int
}

// ClientRoute holds routing information for a single client.
type ClientRoute struct {
	IP      string
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

	// Generate IP pool (10.0.0.2 - 10.0.0.254)
	ipPool := generateIPPool(cfg.IP, cfg.Netmask)

	mgr := &TUNManager{
		device:      device,
		config:      cfg,
		outbound:    outbound,
		clients:     make(map[string]*ClientRoute),
		ipPool:      ipPool,
		nextIPIndex: 0,
	}

	// Start packet dispatcher
	go mgr.dispatchPackets()

	slog.Info("TUN manager initialized", "device", cfg.Name, "ip", cfg.IP, "pool_size", len(ipPool))
	return mgr, nil
}

// generateIPPool creates a list of available client IPs.
func generateIPPool(serverIP, netmask string) []string {
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

// AllocateIP assigns an IP address to a new client.
func (m *TUNManager) AllocateIP() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.nextIPIndex >= len(m.ipPool) {
		return "", fmt.Errorf("IP pool exhausted")
	}

	ip := m.ipPool[m.nextIPIndex]
	m.nextIPIndex++

	return ip, nil
}

// RegisterClient registers a client with its assigned IP and channel.
func (m *TUNManager) RegisterClient(ip string, channel ssh.Channel) *ClientRoute {
	m.mu.Lock()
	defer m.mu.Unlock()

	route := &ClientRoute{
		IP:      ip,
		Channel: channel,
		done:    make(chan struct{}),
	}

	m.clients[ip] = route
	slog.Info("Client registered", "ip", ip, "total_clients", len(m.clients))

	return route
}

// UnregisterClient removes a client and frees its IP.
func (m *TUNManager) UnregisterClient(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if route, exists := m.clients[ip]; exists {
		close(route.done)
		delete(m.clients, ip)
		slog.Info("Client unregistered", "ip", ip, "total_clients", len(m.clients))
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
