package tun

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"uproxy/internal/framing"
)

// ClientRegistry manages client registration, IP allocation, and client lookup.
type ClientRegistry struct {
	Mu        sync.RWMutex            // Exported for testing
	Clients   map[string]*ClientRoute // Exported for testing
	Allocator *IPAllocator            // Exported for testing
}

// NewClientRegistry creates a new client registry with the given IP allocator.
func NewClientRegistry(allocator *IPAllocator) *ClientRegistry {
	return &ClientRegistry{
		Clients:   make(map[string]*ClientRoute),
		Allocator: allocator,
	}
}

// AllocateIP assigns IP addresses (IPv4 and optionally IPv6) to a new client.
func (cr *ClientRegistry) AllocateIP() (ipv4 string, ipv6 string, err error) {
	return cr.Allocator.AllocateIP()
}

// ReleaseIP releases IP addresses back to the pool.
func (cr *ClientRegistry) ReleaseIP(ipv4, ipv6 string) {
	cr.Allocator.ReleaseIP(ipv4, ipv6)
}

// AllocateAndNotifyClient allocates IPs, notifies the client, and registers them.
// This is a convenience method that combines AllocateIP, notification, and RegisterClient.
func (cr *ClientRegistry) AllocateAndNotifyClient(conn net.Conn) (*ClientRoute, string, string, error) {
	// Allocate IPs for this client
	clientIPv4, clientIPv6, err := cr.AllocateIP()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to allocate IP: %w", err)
	}

	slog.Info("IPs allocated for client", "ipv4", clientIPv4, "ipv6", clientIPv6)

	// Send assigned IPs to client
	ipMsg := fmt.Sprintf("%s%s\n", IPAssignmentIPv4Prefix, clientIPv4)
	if clientIPv6 != "" {
		ipMsg += fmt.Sprintf("%s%s\n", IPAssignmentIPv6Prefix, clientIPv6)
	}
	if err := framing.WriteFramed(conn, []byte(ipMsg)); err != nil {
		// Release the allocated IPs since we failed to notify
		cr.ReleaseIP(clientIPv4, clientIPv6)
		return nil, "", "", fmt.Errorf("failed to send IPs to client: %w", err)
	}

	// Register client with registry
	route := cr.RegisterClient(clientIPv4, clientIPv6, conn)
	return route, clientIPv4, clientIPv6, nil
}

// RegisterClient registers a client with its assigned IPs and connection.
func (cr *ClientRegistry) RegisterClient(ipv4, ipv6 string, conn net.Conn) *ClientRoute {
	cr.Mu.Lock()
	defer cr.Mu.Unlock()

	route := &ClientRoute{
		IPv4: ipv4,
		IPv6: ipv6,
		Conn: conn,
		done: make(chan struct{}),
	}

	cr.Clients[ipv4] = route
	if ipv6 != "" {
		// Extract IP without prefix for routing
		if ip, _, err := net.ParseCIDR(ipv6); err == nil {
			cr.Clients[ip.String()] = route
		}
	}

	slog.Info("Client registered", "ipv4", ipv4, "ipv6", ipv6, "total_clients", len(cr.Clients))

	return route
}

// UnregisterClient removes a client and frees its IPs back to the pool.
func (cr *ClientRegistry) UnregisterClient(ipv4, ipv6 string) {
	cr.Mu.Lock()
	defer cr.Mu.Unlock()

	if route, exists := cr.Clients[ipv4]; exists {
		route.doneOnce.Do(func() { close(route.done) })
		delete(cr.Clients, ipv4)
		if ipv6 != "" {
			if ip, _, err := net.ParseCIDR(ipv6); err == nil {
				delete(cr.Clients, ip.String())
			}
		}

		// Release IPs back to allocator
		cr.ReleaseIP(ipv4, ipv6)

		slog.Info("Client unregistered and IPs freed", "ipv4", ipv4, "ipv6", ipv6, "total_clients", len(cr.Clients))
	}
}

// GetClient retrieves a client route by IP address.
func (cr *ClientRegistry) GetClient(ip string) (*ClientRoute, bool) {
	cr.Mu.RLock()
	defer cr.Mu.RUnlock()
	route, exists := cr.Clients[ip]
	return route, exists
}

// CleanupAll closes all client routes and clears the client map.
func (cr *ClientRegistry) CleanupAll() {
	cr.Mu.Lock()
	defer cr.Mu.Unlock()

	// Close all client routes (avoid double-close for dual-stack clients)
	closed := make(map[*ClientRoute]bool)
	for _, route := range cr.Clients {
		if !closed[route] {
			route.doneOnce.Do(func() { close(route.done) })
			closed[route] = true
		}
	}
	cr.Clients = make(map[string]*ClientRoute)
}
