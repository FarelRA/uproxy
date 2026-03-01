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
	// Set IP address
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", cfg.IP, cidrFromNetmask(cfg.Netmask)), "dev", name)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set IP address: %w, output: %s", err, output)
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
	// Set IP address and destination
	cmd := exec.Command("ifconfig", name, cfg.IP, cfg.IP, "netmask", cfg.Netmask, "mtu", fmt.Sprintf("%d", cfg.MTU), "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to configure interface: %w, output: %s", err, output)
	}

	slog.Info("TUN interface configured", "name", name, "ip", cfg.IP, "mtu", cfg.MTU)
	return nil
}

// AddRoute adds a route through the TUN interface
func AddRoute(dest, ifaceName string) error {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("ip", "route", "add", dest, "dev", ifaceName)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add route %s: %w, output: %s", dest, err, output)
		}
	case "darwin":
		// Parse destination to get network and gateway
		cmd := exec.Command("route", "add", "-net", dest, "-interface", ifaceName)
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
