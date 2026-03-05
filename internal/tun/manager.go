package tun

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

// TUNManager manages a single TUN device shared by multiple clients.
// It coordinates device management, client registry, packet routing, and NAT configuration.
type TUNManager struct {
	deviceMgr      *DeviceManager
	ClientRegistry *ClientRegistry // Exported for testing
	packetRouter   *PacketRouter
	natConfig      *NATConfigurator

	ctx    context.Context
	cancel context.CancelFunc
}

// ClientRoute holds routing information for a single client.
type ClientRoute struct {
	IPv4     string
	IPv6     string
	Conn     net.Conn
	done     chan struct{}
	doneOnce sync.Once // Ensures done channel is closed only once
}

// NewTUNManager creates a TUN manager with a shared TUN device.
func NewTUNManager(cfg *Config, outbound string, autoRoute bool) (*TUNManager, error) {
	// Create device manager
	deviceMgr, err := NewDeviceManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create device manager: %w", err)
	}

	// Create NAT configurator
	natConfig := NewNATConfigurator(deviceMgr.Name(), outbound, cfg, autoRoute)

	// Enable NAT if auto-route is enabled
	if err := natConfig.Enable(); err != nil {
		deviceMgr.Close()
		return nil, err
	}

	// Create IP allocator and client registry
	allocator := NewIPAllocator(cfg.IP, cfg.Netmask, cfg.IPv6)
	clientRegistry := NewClientRegistry(allocator)

	// Create context for lifecycle management
	ctx, cancel := context.WithCancel(context.Background())

	// Create packet router
	packetRouter := NewPacketRouter(deviceMgr, clientRegistry, ctx)

	mgr := &TUNManager{
		deviceMgr:      deviceMgr,
		ClientRegistry: clientRegistry,
		packetRouter:   packetRouter,
		natConfig:      natConfig,
		ctx:            ctx,
		cancel:         cancel,
	}

	// Start packet dispatcher
	packetRouter.Start()

	slog.Info("TUN manager initialized", "device", cfg.Name, "ip", cfg.IP, "ipv6", cfg.IPv6)
	return mgr, nil
}

// AllocateIP assigns IP addresses (IPv4 and optionally IPv6) to a new client.
func (m *TUNManager) AllocateIP() (ipv4 string, ipv6 string, err error) {
	return m.ClientRegistry.AllocateIP()
}

// AllocateAndNotifyClient allocates IPs, notifies the client, and registers them.
// This is a convenience method that combines AllocateIP, notification, and RegisterClient.
func (m *TUNManager) AllocateAndNotifyClient(conn net.Conn) (*ClientRoute, string, string, error) {
	return m.ClientRegistry.AllocateAndNotifyClient(conn)
}

// RegisterClient registers a client with its assigned IPs and connection.
func (m *TUNManager) RegisterClient(ipv4, ipv6 string, conn net.Conn) *ClientRoute {
	return m.ClientRegistry.RegisterClient(ipv4, ipv6, conn)
}

// UnregisterClient removes a client and frees its IPs back to the pool.
func (m *TUNManager) UnregisterClient(ipv4, ipv6 string) {
	m.ClientRegistry.UnregisterClient(ipv4, ipv6)
}

// WritePacket writes a packet from a client to the TUN device.
func (m *TUNManager) WritePacket(packet []byte) error {
	_, err := m.deviceMgr.Write(packet)
	return err
}

// Close shuts down the TUN manager and cleans up resources.
func (m *TUNManager) Close() error {
	// Cancel context to stop dispatcher goroutine
	m.cancel()

	// Cleanup clients
	m.ClientRegistry.CleanupAll()

	// Cleanup NAT rules
	m.natConfig.Disable()

	// Close TUN device
	return m.deviceMgr.Close()
}
