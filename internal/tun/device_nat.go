package tun

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
)

// executeIPTablesRule executes an iptables command with the given arguments
// Returns error only if critical is true, otherwise logs warning
func executeIPTablesRule(cmd string, args []string, description string, critical bool) error {
	command := exec.Command(cmd, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		if critical {
			return fmt.Errorf("failed to %s: %w, output: %s", description, err, output)
		}
		slog.Warn(fmt.Sprintf("Failed to %s", description), "error", err, "output", string(output))
	} else {
		slog.Info(description)
	}
	return nil
}

// addIPTablesRule adds an IPv4 iptables rule
func addIPTablesRule(args []string, description string, critical bool) error {
	return executeIPTablesRule("iptables", args, description, critical)
}

// addIP6TablesRule adds an IPv6 ip6tables rule
func addIP6TablesRule(args []string, description string, critical bool) error {
	return executeIPTablesRule("ip6tables", args, description, critical)
}

// deleteIPTablesRule deletes an IPv4 iptables rule
func deleteIPTablesRule(args []string, description string) {
	executeIPTablesRule("iptables", args, description, false)
}

// deleteIP6TablesRule deletes an IPv6 ip6tables rule
func deleteIP6TablesRule(args []string, description string) {
	executeIPTablesRule("ip6tables", args, description, false)
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
		if err := addIPTablesRule(
			[]string{"-t", "nat", "-A", "POSTROUTING", "-s", ipv4Subnet, "-o", outboundIface, "-j", "MASQUERADE"},
			fmt.Sprintf("enable IPv4 NAT for %s via %s", ipv4Subnet, outboundIface),
			true,
		); err != nil {
			return err
		}

		// Allow forwarding from TUN to outbound interface (insert at beginning to bypass REJECT rules)
		addIPTablesRule(
			[]string{"-I", "FORWARD", "1", "-i", tunIface, "-o", outboundIface, "-j", "ACCEPT"},
			"add IPv4 forward rule",
			false,
		)

		// Allow forwarding from outbound to TUN interface (return traffic)
		addIPTablesRule(
			[]string{"-I", "FORWARD", "2", "-i", outboundIface, "-o", tunIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
			"add IPv4 return forward rule",
			false,
		)
	}

	// IPv6 NAT rules - only masquerade traffic from TUN subnet
	if ipv6Subnet != "" {
		if err := addIP6TablesRule(
			[]string{"-t", "nat", "-A", "POSTROUTING", "-s", ipv6Subnet, "-o", outboundIface, "-j", "MASQUERADE"},
			fmt.Sprintf("enable IPv6 NAT for %s via %s", ipv6Subnet, outboundIface),
			false,
		); err == nil {
			// Allow IPv6 forwarding from TUN to outbound interface (insert at beginning to bypass REJECT rules)
			addIP6TablesRule(
				[]string{"-I", "FORWARD", "1", "-i", tunIface, "-o", outboundIface, "-j", "ACCEPT"},
				"add IPv6 forward rule",
				false,
			)

			// Allow IPv6 forwarding from outbound to TUN interface (return traffic)
			addIP6TablesRule(
				[]string{"-I", "FORWARD", "2", "-i", outboundIface, "-o", tunIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
				"add IPv6 return forward rule",
				false,
			)
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
		deleteIPTablesRule(
			[]string{"-t", "nat", "-D", "POSTROUTING", "-s", ipv4Subnet, "-o", outboundIface, "-j", "MASQUERADE"},
			"remove IPv4 NAT rule",
		)
	}
	deleteIPTablesRule(
		[]string{"-D", "FORWARD", "-i", tunIface, "-o", outboundIface, "-j", "ACCEPT"},
		"remove IPv4 forward rule",
	)
	deleteIPTablesRule(
		[]string{"-D", "FORWARD", "-i", outboundIface, "-o", tunIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		"remove IPv4 return forward rule",
	)

	// Remove IPv6 iptables rules
	if ipv6Subnet != "" {
		deleteIP6TablesRule(
			[]string{"-t", "nat", "-D", "POSTROUTING", "-s", ipv6Subnet, "-o", outboundIface, "-j", "MASQUERADE"},
			"remove IPv6 NAT rule",
		)
	}
	deleteIP6TablesRule(
		[]string{"-D", "FORWARD", "-i", tunIface, "-o", outboundIface, "-j", "ACCEPT"},
		"remove IPv6 forward rule",
	)
	deleteIP6TablesRule(
		[]string{"-D", "FORWARD", "-i", outboundIface, "-o", tunIface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		"remove IPv6 return forward rule",
	)

	slog.Info("NAT disabled", "tun", tunIface, "outbound", outboundIface)
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
