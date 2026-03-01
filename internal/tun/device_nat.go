package tun

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
)

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
