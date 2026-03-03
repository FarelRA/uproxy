package tun

import (
	"fmt"
	"log/slog"
	"net"
)

// NATConfigurator manages NAT/iptables rules and IP forwarding.
type NATConfigurator struct {
	deviceName string
	outbound   string
	config     *Config
	autoRoute  bool
	enabled    bool
}

// NewNATConfigurator creates a new NAT configurator.
func NewNATConfigurator(deviceName, outbound string, config *Config, autoRoute bool) *NATConfigurator {
	return &NATConfigurator{
		deviceName: deviceName,
		outbound:   outbound,
		config:     config,
		autoRoute:  autoRoute,
		enabled:    false,
	}
}

// Enable sets up IP forwarding and NAT rules.
func (nc *NATConfigurator) Enable() error {
	if !nc.autoRoute {
		slog.Info("Auto-route disabled, skipping NAT/forwarding setup")
		return nil
	}

	// Enable IP forwarding
	if err := EnableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	// Set up NAT/masquerading with subnet filtering
	ipv4Subnet := buildIPv4NATSubnet(nc.config.IP, nc.config.Netmask)
	ipv6Subnet := nc.config.IPv6 // Already includes /64

	if err := EnableNAT(nc.deviceName, nc.outbound, ipv4Subnet, ipv6Subnet); err != nil {
		return fmt.Errorf("failed to setup NAT: %w", err)
	}

	nc.enabled = true
	return nil
}

// Disable removes NAT rules.
func (nc *NATConfigurator) Disable() {
	if !nc.enabled {
		return
	}

	// Construct subnet strings from config
	ipv4Subnet := buildIPv4NATSubnet(nc.config.IP, nc.config.Netmask)

	ipv6Subnet := ""
	if nc.config.IPv6 != "" {
		// IPv6 is already in CIDR format (e.g., "fd42:cafe:beef::1/64")
		// Extract the network prefix
		if ip, ipnet, err := net.ParseCIDR(nc.config.IPv6); err == nil {
			// Get the network address (zero out host bits)
			networkIP := ip.Mask(ipnet.Mask)
			ones, _ := ipnet.Mask.Size()
			ipv6Subnet = fmt.Sprintf("%s/%d", networkIP.String(), ones)
		}
	}

	DisableNAT(nc.deviceName, nc.outbound, ipv4Subnet, ipv6Subnet)
	nc.enabled = false
}

// BuildIPv4NATSubnet constructs a CIDR subnet string from IP and netmask.
// Exported for testing purposes.
func BuildIPv4NATSubnet(ipv4, netmask string) string {
	return buildIPv4NATSubnet(ipv4, netmask)
}

// buildIPv4NATSubnet constructs a CIDR subnet string from IP and netmask.
func buildIPv4NATSubnet(ipv4, netmask string) string {
	if ipv4 == "" || netmask == "" {
		return ""
	}

	ip := net.ParseIP(ipv4).To4()
	maskIP := net.ParseIP(netmask).To4()
	if ip == nil || maskIP == nil {
		return ""
	}

	mask := net.IPv4Mask(maskIP[0], maskIP[1], maskIP[2], maskIP[3])
	ones, bits := mask.Size()
	if bits != 32 {
		return ""
	}

	networkIP := ip.Mask(mask)
	return fmt.Sprintf("%s/%d", networkIP.String(), ones)
}
