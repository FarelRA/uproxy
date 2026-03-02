package tun

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"sync"
)

// IPAllocator manages IP address allocation for TUN clients
type IPAllocator struct {
	mu sync.Mutex

	// IPv4 configuration
	ipv4Network net.IP
	ipv4Mask    net.IPMask
	serverIPv4  string
	heldIPv4    map[string]bool

	// IPv6 configuration
	ipv6Network net.IP
	ipv6Prefix  int
	serverIPv6  string
	heldIPv6    map[string]bool
}

// NewIPAllocator creates a new IP allocator
func NewIPAllocator(serverIPv4, netmask, serverIPv6 string) *IPAllocator {
	allocator := &IPAllocator{
		serverIPv4: serverIPv4,
		serverIPv6: serverIPv6,
		heldIPv4:   make(map[string]bool),
		heldIPv6:   make(map[string]bool),
	}

	// Parse IPv4 configuration
	if serverIPv4 != "" && netmask != "" {
		allocator.ipv4Network, allocator.ipv4Mask = parseIPv4Config(serverIPv4, netmask)
	}

	// Parse IPv6 configuration
	if serverIPv6 != "" {
		allocator.ipv6Network, allocator.ipv6Prefix = parseIPv6Config(serverIPv6)
	}

	return allocator
}

// AllocateIP assigns IP addresses (IPv4 and optionally IPv6) to a new client
func (a *IPAllocator) AllocateIP() (ipv4 string, ipv6 string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Generate random IPv4
	ipv4, err = a.generateRandomIPv4()
	if err != nil {
		return "", "", fmt.Errorf("failed to allocate IPv4: %w", err)
	}
	a.heldIPv4[ipv4] = true

	// Generate random IPv6 if configured
	if a.ipv6Network != nil {
		ipv6, err = a.generateRandomIPv6()
		if err != nil {
			// IPv6 allocation failed, but IPv4 succeeded - continue with IPv4 only
			slog.Warn("Failed to allocate IPv6", "error", err)
			ipv6 = ""
		} else {
			a.heldIPv6[ipv6] = true
		}
	}

	return ipv4, ipv6, nil
}

// ReleaseIP releases previously allocated IP addresses
func (a *IPAllocator) ReleaseIP(ipv4, ipv6 string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ipv4 != "" {
		delete(a.heldIPv4, ipv4)
	}
	if ipv6 != "" {
		delete(a.heldIPv6, ipv6)
	}
}

// generateRandomOctet generates a random byte in range 2-254
func generateRandomOctet() (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(253))
	if err != nil {
		return 0, err
	}
	return byte(n.Int64() + 2), nil
}

// generateRandomIPv4 generates a random IPv4 address within the configured network
func (a *IPAllocator) generateRandomIPv4() (string, error) {
	if a.ipv4Network == nil {
		return "", fmt.Errorf("IPv4 network not configured")
	}

	maxAttempts := 500 // Prevent infinite loops

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Generate random last octet (2-254, skip .0, .1, .255)
		lastOctet, err := generateRandomOctet()
		if err != nil {
			continue
		}

		// Construct IP
		ip := make(net.IP, 4)
		copy(ip, a.ipv4Network)
		ip[3] = lastOctet

		ipStr := ip.String()

		// Skip server IP
		if ipStr == a.serverIPv4 {
			continue
		}

		// Check if already held
		if !a.heldIPv4[ipStr] {
			return ipStr, nil
		}
	}

	return "", fmt.Errorf("IPv4 pool exhausted or too many collisions")
}

// generateRandomIPv6 generates a random IPv6 address within the configured network
func (a *IPAllocator) generateRandomIPv6() (string, error) {
	if a.ipv6Network == nil {
		return "", fmt.Errorf("IPv6 network not configured")
	}

	maxAttempts := 500

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Generate random last octet (2-254)
		lastOctet, err := generateRandomOctet()
		if err != nil {
			continue
		}

		// Construct IP
		ip := make(net.IP, 16)
		copy(ip, a.ipv6Network)
		ip[15] = lastOctet

		ipStr := fmt.Sprintf("%s/%d", ip.String(), a.ipv6Prefix)

		// Skip server IP
		if ipStr == a.serverIPv6 {
			continue
		}

		// Check if already held
		if !a.heldIPv6[ipStr] {
			return ipStr, nil
		}
	}

	return "", fmt.Errorf("IPv6 pool exhausted or too many collisions")
}

// parseIPv4Config parses IPv4 configuration and returns network address and mask
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

// parseIPv6Config parses IPv6 CIDR and returns network address and prefix length
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
