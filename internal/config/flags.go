package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// AddCommonFlags adds flags that are shared between client and server
func AddCommonFlags(cmd *cobra.Command, cfg *CommonConfig) {
	// Logging flags
	cmd.Flags().StringVar(&cfg.LogLevel, "log-level", DefaultLogLevel, "Log level (debug, info, warn, error)")
	cmd.Flags().StringVar(&cfg.LogFormat, "log-format", DefaultLogFormat, "Log format (console, json)")

	// Network flags
	cmd.Flags().DurationVar(&cfg.IdleTimeout, "idle-timeout", DefaultIdleTimeout, "Idle timeout for connections")
	cmd.Flags().DurationVar(&cfg.ReconnectInterval, "reconnect-interval", DefaultReconnectInterval, "Reconnect interval on failure")
	cmd.Flags().IntVar(&cfg.TCPBufSize, "tcp-buf", DefaultTCPBufSize, "TCP buffer size")
	cmd.Flags().IntVar(&cfg.UDPSockBuf, "udp-sockbuf", DefaultUDPSockBuf, "UDP socket buffer size")

	// KCP flags
	cmd.Flags().IntVar(&cfg.KCP.NoDelay, "kcp-nodelay", DefaultKCPNoDelay, "KCP nodelay mode (0=disabled, 1=enabled)")
	cmd.Flags().IntVar(&cfg.KCP.Interval, "kcp-interval", DefaultKCPInterval, "KCP internal update interval (ms)")
	cmd.Flags().IntVar(&cfg.KCP.Resend, "kcp-resend", DefaultKCPResend, "KCP fast resend mode")
	cmd.Flags().IntVar(&cfg.KCP.NoCongestionCtrl, "kcp-nc", DefaultKCPNC, "KCP no congestion control (0=disabled, 1=enabled)")
	cmd.Flags().IntVar(&cfg.KCP.SndWnd, "kcp-sndwnd", DefaultKCPSndWnd, "KCP send window size")
	cmd.Flags().IntVar(&cfg.KCP.RcvWnd, "kcp-rcvwnd", DefaultKCPRcvWnd, "KCP receive window size")
	cmd.Flags().IntVar(&cfg.KCP.MTU, "kcp-mtu", DefaultKCPMTU, "KCP maximum transmission unit")

	// SSH flags
	cmd.Flags().StringVar(&cfg.SSH.Dir, "ssh-dir", "", "SSH directory (default: ~/.ssh)")
	cmd.Flags().StringVar(&cfg.SSH.PrivateKey, "ssh-private-key", "", "SSH private key file (default: <ssh-dir>/id_ed25519)")
}

// AddServerFlags adds server-specific flags
func AddServerFlags(cmd *cobra.Command, cfg *ServerConfig) {
	AddCommonFlags(cmd, &cfg.CommonConfig)

	// Server-specific flags
	cmd.Flags().StringVarP(&cfg.ListenAddr, "listen", "l", ":6000", "Listen address (host:port)")
	cmd.Flags().StringVarP(&cfg.Outbound, "outbound", "o", "", "Outbound interface for proxy connections")
	cmd.Flags().DurationVar(&cfg.ProxyDialTimeout, "proxy-dial-timeout", DefaultProxyDialTimeout, "Timeout for proxy dial operations")

	// SSH server flags
	cmd.Flags().StringVar(&cfg.SSH.AuthorizedKeys, "ssh-authorized-keys", "", "SSH authorized keys file (default: <ssh-dir>/authorized_keys)")

	// TUN flags
	cmd.Flags().StringVar(&cfg.TUN.Name, "tun-name", "tun0", "TUN device name")
	cmd.Flags().StringVar(&cfg.TUN.IP, "tun-ip", DefaultServerTUNIP, "TUN device IPv4 address")
	cmd.Flags().StringVar(&cfg.TUN.Netmask, "tun-netmask", DefaultServerTUNNetmask, "TUN device netmask")
	cmd.Flags().StringVar(&cfg.TUN.IPv6, "tun-ipv6", DefaultServerTUNIPv6, "TUN device IPv6 address")
	cmd.Flags().IntVar(&cfg.TUN.MTU, "tun-mtu", DefaultTUNMTU, "TUN device MTU")
	cmd.Flags().BoolVar(&cfg.TUN.AutoRoute, "tun-auto-route", true, "Automatically configure routing for TUN clients")
}

// AddClientFlags adds client-specific flags
func AddClientFlags(cmd *cobra.Command, cfg *ClientConfig) {
	AddCommonFlags(cmd, &cfg.CommonConfig)

	// Client-specific flags
	cmd.Flags().StringVarP(&cfg.Mode, "mode", "m", "auto", "Proxy mode (auto, socks5, tun)")
	cmd.Flags().StringVarP(&cfg.ListenAddr, "listen", "l", "127.0.0.1:1080", "SOCKS5 listen address (host:port)")
	cmd.Flags().StringVarP(&cfg.ServerAddr, "server", "s", "", "Server address (host:port) [required]")
	cmd.Flags().DurationVar(&cfg.SSHTimeout, "ssh-timeout", DefaultSSHTimeout, "SSH connection timeout")

	// SSH client flags
	cmd.Flags().StringVar(&cfg.SSH.KnownHosts, "ssh-known-hosts", "", "SSH known hosts file (default: <ssh-dir>/known_hosts)")

	// TUN flags
	cmd.Flags().StringVar(&cfg.TUN.Name, "tun-name", "tun0", "TUN device name")
	cmd.Flags().IntVar(&cfg.TUN.MTU, "tun-mtu", DefaultTUNMTU, "TUN device MTU")
	cmd.Flags().StringVar(&cfg.TUN.Routes, "tun-routes", "", "Additional routes to add (comma-separated)")
	cmd.Flags().BoolVar(&cfg.TUN.AutoRoute, "tun-auto-route", true, "Automatically configure default route through TUN")

	// Mark required flags
	cmd.MarkFlagRequired("server")
}

// SetupSSHPaths sets up default SSH paths if not specified
func SetupSSHPaths(cfg *SSHConfig, isServer bool) {
	if cfg.Dir == "" {
		cfg.Dir = defaultSSHDir()
	}

	if cfg.PrivateKey == "" {
		cfg.PrivateKey = cfg.Dir + "/id_ed25519"
	}

	if isServer && cfg.AuthorizedKeys == "" {
		cfg.AuthorizedKeys = cfg.Dir + "/authorized_keys"
	}

	if !isServer && cfg.KnownHosts == "" {
		cfg.KnownHosts = cfg.Dir + "/known_hosts"
	}
}

func defaultSSHDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".ssh"
	}
	return filepath.Join(home, ".ssh")
}

// InitializeCommon performs common initialization steps for both client and server
func InitializeCommon(logLevel, logFormat string, sshCfg *SSHConfig, isServer bool, initLogger func(string, string)) {
	initLogger(logLevel, logFormat)
	SetupSSHPaths(sshCfg, isServer)
}
