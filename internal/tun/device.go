package tun

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/songgao/water"
)

type Config struct {
	Name    string
	IP      string
	Netmask string
	IPv6    string // IPv6 address with prefix (e.g., "fd00::1/64")
	MTU     int
}

// CreateTUN creates and configures a TUN device
func CreateTUN(cfg *Config) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	// On Linux, we can specify the device name
	if runtime.GOOS == "linux" {
		config.Name = cfg.Name
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	slog.Info("TUN device created", "name", iface.Name())

	// Configure the interface
	if err := configureTUN(iface.Name(), cfg); err != nil {
		iface.Close()
		return nil, fmt.Errorf("failed to configure TUN device: %w", err)
	}

	return iface, nil
}

// configureTUN configures the TUN interface with IP address and brings it up
func configureTUN(name string, cfg *Config) error {
	switch runtime.GOOS {
	case "linux":
		return configureLinux(name, cfg)
	case "darwin":
		return configureDarwin(name, cfg)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

func configureLinux(name string, cfg *Config) error {
	// Set IPv4 address
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", cfg.IP, cidrFromNetmask(cfg.Netmask)), "dev", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set IP address: %w, output: %s", err, output)
	}

	// Set IPv6 address if provided
	if cfg.IPv6 != "" {
		cmd = exec.Command("ip", "-6", "addr", "add", cfg.IPv6, "dev", name)
		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("Failed to set IPv6 address", "error", err, "output", string(output))
		} else {
			slog.Info("IPv6 address configured", "name", name, "ipv6", cfg.IPv6)
		}
	}

	// Set MTU
	cmd = exec.Command("ip", "link", "set", "dev", name, "mtu", fmt.Sprintf("%d", cfg.MTU))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set MTU: %w, output: %s", err, output)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", name, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w, output: %s", err, output)
	}

	slog.Info("TUN interface configured", "name", name, "ip", cfg.IP, "mtu", cfg.MTU)
	return nil
}

func configureDarwin(name string, cfg *Config) error {
	// Set IPv4 address and destination
	cmd := exec.Command("ifconfig", name, cfg.IP, cfg.IP, "netmask", cfg.Netmask, "mtu", fmt.Sprintf("%d", cfg.MTU), "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to configure interface: %w, output: %s", err, output)
	}

	// Set IPv6 address if provided
	if cfg.IPv6 != "" {
		cmd = exec.Command("ifconfig", name, "inet6", cfg.IPv6)
		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("Failed to set IPv6 address", "error", err, "output", string(output))
		} else {
			slog.Info("IPv6 address configured", "name", name, "ipv6", cfg.IPv6)
		}
	}

	slog.Info("TUN interface configured", "name", name, "ip", cfg.IP, "mtu", cfg.MTU)
	return nil
}

// AddRoute adds a route through the TUN interface
func AddRoute(dest, ifaceName string) error {
	// Detect if this is an IPv6 route
	isIPv6 := strings.Contains(dest, ":")

	switch runtime.GOOS {
	case "linux":
		args := []string{"route", "add", dest, "dev", ifaceName}
		if isIPv6 {
			args = []string{"-6", "route", "add", dest, "dev", ifaceName}
		}
		cmd := exec.Command("ip", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add route %s: %w, output: %s", dest, err, output)
		}
	case "darwin":
		// Parse destination to get network and gateway
		args := []string{"add"}
		if isIPv6 {
			args = append(args, "-inet6")
		}
		args = append(args, "-net", dest, "-interface", ifaceName)
		cmd := exec.Command("route", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add route %s: %w, output: %s", dest, err, output)
		}
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	slog.Info("Route added", "dest", dest, "interface", ifaceName)
	return nil
}

// cidrFromNetmask converts a netmask to CIDR notation
func cidrFromNetmask(netmask string) string {
	ip := net.ParseIP(netmask)
	if ip == nil {
		return "24" // default
	}

	mask := net.IPMask(ip.To4())
	ones, _ := mask.Size()
	return fmt.Sprintf("%d", ones)
}

// ParseRoutes parses comma-separated route list
func ParseRoutes(routes string) []string {
	if routes == "" {
		return nil
	}

	parts := strings.Split(routes, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// EnableIPForwarding enables IP forwarding in the kernel
func EnableIPForwarding() error {
	if runtime.GOOS != "linux" {
		return nil // Only needed on Linux
	}

	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w, output: %s", err, output)
	}

	cmd = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("Failed to enable IPv6 forwarding", "error", err, "output", string(output))
	}

	slog.Info("IP forwarding enabled")
	return nil
}

// EnableNAT sets up NAT/masquerading for the TUN interface (both IPv4 and IPv6)
func EnableNAT(tunIface, outboundIface, ipv4Subnet, ipv6Subnet string) error {
	if runtime.GOOS != "linux" {
		return nil // Only needed on Linux
	}

	// If no outbound interface specified, try to detect default route interface
	if outboundIface == "" {
		iface, err := getDefaultInterface()
		if err != nil {
			return fmt.Errorf("failed to detect default interface: %w", err)
		}
		outboundIface = iface
	}

	// IPv4 NAT rules - only masquerade traffic from TUN subnet
	if ipv4Subnet != "" {
		cmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", ipv4Subnet, "-o", outboundIface, "-j", "MASQUERADE")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to enable IPv4 NAT: %w, output: %s", err, output)
		}
		slog.Info("IPv4 NAT enabled", "subnet", ipv4Subnet, "outbound", outboundIface)

		// Allow forwarding from TUN to outbound interface (insert at beginning to bypass REJECT rules)
		cmd = exec.Command("iptables", "-I", "FORWARD", "1", "-i", tunIface, "-o", outboundIface, "-j", "ACCEPT")
		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("Failed to add IPv4 forward rule", "error", err, "output", string(output))
		}

		// Allow forwarding from outbound to TUN interface (return traffic)
		cmd = exec.Command("iptables", "-I", "FORWARD", "2", "-i", outboundIface, "-o", tunIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("Failed to add IPv4 return forward rule", "error", err, "output", string(output))
		}
	}

	// IPv6 NAT rules - only masquerade traffic from TUN subnet
	if ipv6Subnet != "" {
		cmd := exec.Command("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", ipv6Subnet, "-o", outboundIface, "-j", "MASQUERADE")
		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("Failed to enable IPv6 NAT", "error", err, "output", string(output))
		} else {
			slog.Info("IPv6 NAT enabled", "subnet", ipv6Subnet, "outbound", outboundIface)

			// Allow IPv6 forwarding from TUN to outbound interface (insert at beginning to bypass REJECT rules)
			cmd = exec.Command("ip6tables", "-I", "FORWARD", "1", "-i", tunIface, "-o", outboundIface, "-j", "ACCEPT")
			if output, err := cmd.CombinedOutput(); err != nil {
				slog.Warn("Failed to add IPv6 forward rule", "error", err, "output", string(output))
			}

			// Allow IPv6 forwarding from outbound to TUN interface (return traffic)
			cmd = exec.Command("ip6tables", "-I", "FORWARD", "2", "-i", outboundIface, "-o", tunIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
			if output, err := cmd.CombinedOutput(); err != nil {
				slog.Warn("Failed to add IPv6 return forward rule", "error", err, "output", string(output))
			}
		}
	}

	slog.Info("NAT enabled", "tun", tunIface, "outbound", outboundIface)
	return nil
}

// DisableNAT removes NAT/masquerading rules (both IPv4 and IPv6)
func DisableNAT(tunIface, outboundIface, ipv4Subnet, ipv6Subnet string) {
	if runtime.GOOS != "linux" {
		return
	}

	if outboundIface == "" {
		iface, err := getDefaultInterface()
		if err != nil {
			slog.Warn("Failed to get default interface for NAT cleanup", "error", err)
			return
		}
		outboundIface = iface
	}

	// Remove IPv4 iptables rules (must match exactly what EnableNAT created)
	if ipv4Subnet != "" {
		exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", ipv4Subnet, "-o", outboundIface, "-j", "MASQUERADE").Run()
	}
	exec.Command("iptables", "-D", "FORWARD", "-i", tunIface, "-o", outboundIface, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-i", outboundIface, "-o", tunIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()

	// Remove IPv6 ip6tables rules (must match exactly what EnableNAT created)
	if ipv6Subnet != "" {
		exec.Command("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-s", ipv6Subnet, "-o", outboundIface, "-j", "MASQUERADE").Run()
	}
	exec.Command("ip6tables", "-D", "FORWARD", "-i", tunIface, "-o", outboundIface, "-j", "ACCEPT").Run()
	exec.Command("ip6tables", "-D", "FORWARD", "-i", outboundIface, "-o", tunIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()

	slog.Info("NAT disabled and rules cleaned up", "tun", tunIface, "outbound", outboundIface, "ipv4_subnet", ipv4Subnet, "ipv6_subnet", ipv6Subnet)
}

// getDefaultInterface returns the default network interface
func getDefaultInterface() (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// Parse output like: "default via 192.168.1.1 dev eth0 ..."
	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("could not determine default interface")
}
