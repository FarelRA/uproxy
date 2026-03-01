package tun

import (
	"sync"
	"testing"

	"uproxy/internal/testutil"
)

// TestAllocateIP tests IP allocation through TUNManager
func TestAllocateIP(t *testing.T) {
	mgr := &TUNManager{
		clients:   make(map[string]*ClientRoute),
		allocator: NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64"),
	}

	// Allocate first IP
	ipv4, ipv6, err := mgr.AllocateIP()
	if err != nil {
		t.Fatalf("AllocateIP failed: %v", err)
	}

	if ipv4 == "" {
		t.Error("Expected non-empty IPv4")
	}
	if ipv6 == "" {
		t.Error("Expected non-empty IPv6")
	}

	// Allocate second IP - should be different
	ipv4_2, ipv6_2, err := mgr.AllocateIP()
	if err != nil {
		t.Fatalf("Second AllocateIP failed: %v", err)
	}

	if ipv4 == ipv4_2 {
		t.Error("Expected different IPv4 addresses")
	}
	if ipv6 == ipv6_2 {
		t.Error("Expected different IPv6 addresses")
	}
}

// TestRegisterClient tests client registration
func TestRegisterClient(t *testing.T) {
	mgr := &TUNManager{
		clients:   make(map[string]*ClientRoute),
		allocator: NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64"),
	}

	channel := testutil.NewMockSSHChannel()
	ipv4 := "10.0.0.2"
	ipv6 := "fd00::2/64"

	route := mgr.RegisterClient(ipv4, ipv6, channel)

	if route == nil {
		t.Fatal("RegisterClient returned nil")
	}

	if route.IPv4 != ipv4 {
		t.Errorf("Expected IPv4 %s, got %s", ipv4, route.IPv4)
	}

	if route.IPv6 != ipv6 {
		t.Errorf("Expected IPv6 %s, got %s", ipv6, route.IPv6)
	}

	if route.Channel == nil {
		t.Error("Expected channel to be set")
	}

	// Verify client is in map
	mgr.mu.RLock()
	_, exists := mgr.clients[ipv4]
	mgr.mu.RUnlock()

	if !exists {
		t.Error("Client not found in clients map")
	}
}

// TestUnregisterClient tests client unregistration
func TestUnregisterClient(t *testing.T) {
	mgr := &TUNManager{
		clients:   make(map[string]*ClientRoute),
		allocator: NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64"),
	}

	channel := testutil.NewMockSSHChannel()
	ipv4 := "10.0.0.2"
	ipv6 := "fd00::2/64"

	// Register client
	mgr.RegisterClient(ipv4, ipv6, channel)

	// Verify registered
	mgr.mu.RLock()
	_, exists := mgr.clients[ipv4]
	mgr.mu.RUnlock()
	if !exists {
		t.Fatal("Client should be registered")
	}

	// Unregister client
	mgr.UnregisterClient(ipv4, ipv6)

	// Verify unregistered
	mgr.mu.RLock()
	_, exists = mgr.clients[ipv4]
	mgr.mu.RUnlock()
	if exists {
		t.Error("Client should be unregistered")
	}
}

// TestConcurrentClientOperations tests thread-safety of client operations
func TestConcurrentClientOperations(t *testing.T) {
	mgr := &TUNManager{
		clients:   make(map[string]*ClientRoute),
		allocator: NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64"),
	}

	const numClients = 50
	var wg sync.WaitGroup

	// Concurrently register clients
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			ipv4, ipv6, err := mgr.AllocateIP()
			if err != nil {
				t.Errorf("AllocateIP failed: %v", err)
				return
			}

			channel := testutil.NewMockSSHChannel()
			route := mgr.RegisterClient(ipv4, ipv6, channel)
			if route == nil {
				t.Error("RegisterClient returned nil")
			}
		}(i)
	}

	wg.Wait()

	// Verify all clients registered
	mgr.mu.RLock()
	clientCount := len(mgr.clients)
	mgr.mu.RUnlock()

	// Note: clientCount might be > numClients due to dual-stack (IPv4 + IPv6)
	if clientCount < numClients {
		t.Errorf("Expected at least %d clients, got %d", numClients, clientCount)
	}
}

// TestRegisterUnregisterCycle tests repeated register/unregister cycles
func TestRegisterUnregisterCycle(t *testing.T) {
	mgr := &TUNManager{
		clients:   make(map[string]*ClientRoute),
		allocator: NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64"),
	}

	ipv4 := "10.0.0.2"
	ipv6 := "fd00::2/64"

	for i := 0; i < 10; i++ {
		// Register
		channel := testutil.NewMockSSHChannel()
		route := mgr.RegisterClient(ipv4, ipv6, channel)
		if route == nil {
			t.Fatalf("Iteration %d: RegisterClient failed", i)
		}

		// Verify registered
		mgr.mu.RLock()
		_, exists := mgr.clients[ipv4]
		mgr.mu.RUnlock()
		if !exists {
			t.Fatalf("Iteration %d: Client not registered", i)
		}

		// Unregister
		mgr.UnregisterClient(ipv4, ipv6)

		// Verify unregistered
		mgr.mu.RLock()
		_, exists = mgr.clients[ipv4]
		mgr.mu.RUnlock()
		if exists {
			t.Fatalf("Iteration %d: Client still registered", i)
		}
	}
}

// TestMultipleClientsWithSameIPv6Prefix tests handling of IPv6 addresses
func TestMultipleClientsWithDifferentIPs(t *testing.T) {
	mgr := &TUNManager{
		clients:   make(map[string]*ClientRoute),
		allocator: NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64"),
	}

	clients := []struct {
		ipv4 string
		ipv6 string
	}{
		{"10.0.0.2", "fd00::2/64"},
		{"10.0.0.3", "fd00::3/64"},
		{"10.0.0.4", "fd00::4/64"},
	}

	// Register all clients
	for _, c := range clients {
		channel := testutil.NewMockSSHChannel()
		route := mgr.RegisterClient(c.ipv4, c.ipv6, channel)
		if route == nil {
			t.Fatalf("Failed to register client %s", c.ipv4)
		}
	}

	// Verify all clients are registered
	for _, c := range clients {
		mgr.mu.RLock()
		_, exists := mgr.clients[c.ipv4]
		mgr.mu.RUnlock()
		if !exists {
			t.Errorf("Client %s not found", c.ipv4)
		}
	}

	// Unregister middle client
	mgr.UnregisterClient(clients[1].ipv4, clients[1].ipv6)

	// Verify first and third still exist
	mgr.mu.RLock()
	_, exists0 := mgr.clients[clients[0].ipv4]
	_, exists1 := mgr.clients[clients[1].ipv4]
	_, exists2 := mgr.clients[clients[2].ipv4]
	mgr.mu.RUnlock()

	if !exists0 {
		t.Error("First client should still exist")
	}
	if exists1 {
		t.Error("Second client should be removed")
	}
	if !exists2 {
		t.Error("Third client should still exist")
	}
}

// TestUnregisterNonexistentClient tests unregistering a client that doesn't exist
func TestUnregisterNonexistentClient(t *testing.T) {
	mgr := &TUNManager{
		clients:   make(map[string]*ClientRoute),
		allocator: NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64"),
	}

	// Should not panic
	mgr.UnregisterClient("10.0.0.99", "fd00::99/64")

	// Verify no clients
	mgr.mu.RLock()
	count := len(mgr.clients)
	mgr.mu.RUnlock()

	if count != 0 {
		t.Errorf("Expected 0 clients, got %d", count)
	}
}

// BenchmarkRegisterClient benchmarks client registration
func BenchmarkRegisterClient(b *testing.B) {
	mgr := &TUNManager{
		clients:   make(map[string]*ClientRoute),
		allocator: NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ipv4, ipv6, _ := mgr.AllocateIP()
		channel := testutil.NewMockSSHChannel()
		mgr.RegisterClient(ipv4, ipv6, channel)
	}
}

// BenchmarkConcurrentRegister benchmarks concurrent client registration
func BenchmarkConcurrentRegister(b *testing.B) {
	mgr := &TUNManager{
		clients:   make(map[string]*ClientRoute),
		allocator: NewIPAllocator("10.0.0.1", "255.255.255.0", "fd00::1/64"),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ipv4, ipv6, _ := mgr.AllocateIP()
			channel := testutil.NewMockSSHChannel()
			mgr.RegisterClient(ipv4, ipv6, channel)
		}
	})
}
