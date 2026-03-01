package tun

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"

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
