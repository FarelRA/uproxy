package config

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestNewDefaultCommonConfig(t *testing.T) {
	cfg := NewDefaultCommonConfig()

	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("Expected LogLevel %s, got %s", DefaultLogLevel, cfg.LogLevel)
	}
	if cfg.LogFormat != DefaultLogFormat {
		t.Errorf("Expected LogFormat %s, got %s", DefaultLogFormat, cfg.LogFormat)
	}
	if cfg.IdleTimeout != DefaultIdleTimeout {
		t.Errorf("Expected IdleTimeout %v, got %v", DefaultIdleTimeout, cfg.IdleTimeout)
	}
	if cfg.ReconnectInterval != DefaultReconnectInterval {
		t.Errorf("Expected ReconnectInterval %v, got %v", DefaultReconnectInterval, cfg.ReconnectInterval)
	}
	if cfg.TCPBufSize != DefaultTCPBufSize {
		t.Errorf("Expected TCPBufSize %d, got %d", DefaultTCPBufSize, cfg.TCPBufSize)
	}
	if cfg.UDPSockBuf != DefaultUDPSockBuf {
		t.Errorf("Expected UDPSockBuf %d, got %d", DefaultUDPSockBuf, cfg.UDPSockBuf)
	}
}

func TestNewDefaultServerConfig(t *testing.T) {
	cfg := NewDefaultServerConfig()

	// Test common config is initialized
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("Expected LogLevel %s, got %s", DefaultLogLevel, cfg.LogLevel)
	}

	// Test server-specific defaults
	if cfg.ListenAddr != ":6000" {
		t.Errorf("Expected ListenAddr :6000, got %s", cfg.ListenAddr)
	}
	if cfg.ProxyDialTimeout != DefaultProxyDialTimeout {
		t.Errorf("Expected ProxyDialTimeout %v, got %v", DefaultProxyDialTimeout, cfg.ProxyDialTimeout)
	}

	// Test TUN defaults
	if cfg.TUN.Name != "tun0" {
		t.Errorf("Expected TUN.Name tun0, got %s", cfg.TUN.Name)
	}
	if cfg.TUN.IP != DefaultServerTUNIP {
		t.Errorf("Expected TUN.IP %s, got %s", DefaultServerTUNIP, cfg.TUN.IP)
	}
	if cfg.TUN.Netmask != DefaultServerTUNNetmask {
		t.Errorf("Expected TUN.Netmask %s, got %s", DefaultServerTUNNetmask, cfg.TUN.Netmask)
	}
	if cfg.TUN.IPv6 != DefaultServerTUNIPv6 {
		t.Errorf("Expected TUN.IPv6 %s, got %s", DefaultServerTUNIPv6, cfg.TUN.IPv6)
	}
	if cfg.TUN.MTU != DefaultTUNMTU {
		t.Errorf("Expected TUN.MTU %d, got %d", DefaultTUNMTU, cfg.TUN.MTU)
	}
	if !cfg.TUN.AutoRoute {
		t.Error("Expected TUN.AutoRoute to be true")
	}
}

func TestNewDefaultClientConfig(t *testing.T) {
	cfg := NewDefaultClientConfig()

	// Test common config is initialized
	if cfg.LogLevel != DefaultLogLevel {
		t.Errorf("Expected LogLevel %s, got %s", DefaultLogLevel, cfg.LogLevel)
	}

	// Test client-specific defaults
	if cfg.Mode != "auto" {
		t.Errorf("Expected Mode auto, got %s", cfg.Mode)
	}
	if cfg.ListenAddr != "127.0.0.1:1080" {
		t.Errorf("Expected ListenAddr 127.0.0.1:1080, got %s", cfg.ListenAddr)
	}
	if cfg.SSHTimeout != DefaultSSHTimeout {
		t.Errorf("Expected SSHTimeout %v, got %v", DefaultSSHTimeout, cfg.SSHTimeout)
	}

	// Test TUN defaults
	if cfg.TUN.Name != "tun0" {
		t.Errorf("Expected TUN.Name tun0, got %s", cfg.TUN.Name)
	}
	if cfg.TUN.MTU != DefaultTUNMTU {
		t.Errorf("Expected TUN.MTU %d, got %d", DefaultTUNMTU, cfg.TUN.MTU)
	}
	if !cfg.TUN.AutoRoute {
		t.Error("Expected TUN.AutoRoute to be true")
	}
}

func TestAddCommonFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cfg := &CommonConfig{}

	AddCommonFlags(cmd, cfg)

	// Verify flags were added
	flags := []string{
		"log-level", "log-format",
		"idle-timeout", "reconnect-interval",
		"tcp-buf", "udp-sockbuf",
		"ssh-dir", "ssh-private-key",
	}

	for _, flagName := range flags {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Errorf("Expected flag %s to be added", flagName)
		}
	}

	// Test setting values through flags
	cmd.Flags().Set("log-level", "debug")
	if cfg.LogLevel != "debug" {
		t.Errorf("Expected LogLevel debug, got %s", cfg.LogLevel)
	}

	cmd.Flags().Set("tcp-buf", "65536")
	if cfg.TCPBufSize != 65536 {
		t.Errorf("Expected TCPBufSize 65536, got %d", cfg.TCPBufSize)
	}
}

func TestAddServerFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cfg := &ServerConfig{}

	AddServerFlags(cmd, cfg)

	// Verify common flags were added
	if cmd.Flags().Lookup("log-level") == nil {
		t.Error("Expected common flags to be added")
	}

	// Verify server-specific flags were added
	serverFlags := []string{
		"listen", "outbound", "proxy-dial-timeout",
		"ssh-authorized-keys",
		"tun-name", "tun-ip", "tun-netmask", "tun-ipv6", "tun-mtu", "tun-auto-route",
	}

	for _, flagName := range serverFlags {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Errorf("Expected server flag %s to be added", flagName)
		}
	}

	// Test setting values
	cmd.Flags().Set("listen", ":8080")
	if cfg.ListenAddr != ":8080" {
		t.Errorf("Expected ListenAddr :8080, got %s", cfg.ListenAddr)
	}

	cmd.Flags().Set("tun-ip", "10.0.1.1")
	if cfg.TUN.IP != "10.0.1.1" {
		t.Errorf("Expected TUN.IP 10.0.1.1, got %s", cfg.TUN.IP)
	}
}

func TestAddClientFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cfg := &ClientConfig{}

	AddClientFlags(cmd, cfg)

	// Verify common flags were added
	if cmd.Flags().Lookup("log-level") == nil {
		t.Error("Expected common flags to be added")
	}

	// Verify client-specific flags were added
	clientFlags := []string{
		"mode", "listen", "server", "ssh-timeout",
		"ssh-known-hosts",
		"tun-name", "tun-mtu", "tun-routes", "tun-auto-route",
	}

	for _, flagName := range clientFlags {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Errorf("Expected client flag %s to be added", flagName)
		}
	}

	// Test setting values
	cmd.Flags().Set("mode", "socks5")
	if cfg.Mode != "socks5" {
		t.Errorf("Expected Mode socks5, got %s", cfg.Mode)
	}

	cmd.Flags().Set("server", "example.com:6000")
	if cfg.ServerAddr != "example.com:6000" {
		t.Errorf("Expected ServerAddr example.com:6000, got %s", cfg.ServerAddr)
	}

	cmd.Flags().Set("tun-routes", "192.168.1.0/24,10.0.0.0/8")
	if cfg.TUN.Routes != "192.168.1.0/24,10.0.0.0/8" {
		t.Errorf("Expected TUN.Routes to be set, got %s", cfg.TUN.Routes)
	}
}

func TestSetupSSHPaths(t *testing.T) {
	defaultDir := defaultSSHDir()
	defaultPrivateKey := filepath.Join(defaultDir, "id_ed25519")
	defaultAuthorizedKeys := filepath.Join(defaultDir, "authorized_keys")
	defaultKnownHosts := filepath.Join(defaultDir, "known_hosts")

	tests := []struct {
		name     string
		cfg      SSHConfig
		isServer bool
		expected SSHConfig
	}{
		{
			name:     "empty config server",
			cfg:      SSHConfig{},
			isServer: true,
			expected: SSHConfig{
				Dir:            defaultDir,
				PrivateKey:     defaultPrivateKey,
				AuthorizedKeys: defaultAuthorizedKeys,
			},
		},
		{
			name:     "empty config client",
			cfg:      SSHConfig{},
			isServer: false,
			expected: SSHConfig{
				Dir:        defaultDir,
				PrivateKey: defaultPrivateKey,
				KnownHosts: defaultKnownHosts,
			},
		},
		{
			name: "custom dir server",
			cfg: SSHConfig{
				Dir: "/custom/ssh",
			},
			isServer: true,
			expected: SSHConfig{
				Dir:            "/custom/ssh",
				PrivateKey:     "/custom/ssh/id_ed25519",
				AuthorizedKeys: "/custom/ssh/authorized_keys",
			},
		},
		{
			name: "custom dir client",
			cfg: SSHConfig{
				Dir: "/custom/ssh",
			},
			isServer: false,
			expected: SSHConfig{
				Dir:        "/custom/ssh",
				PrivateKey: "/custom/ssh/id_ed25519",
				KnownHosts: "/custom/ssh/known_hosts",
			},
		},
		{
			name: "custom private key",
			cfg: SSHConfig{
				PrivateKey: "/custom/key",
			},
			isServer: true,
			expected: SSHConfig{
				Dir:            defaultDir,
				PrivateKey:     "/custom/key",
				AuthorizedKeys: defaultAuthorizedKeys,
			},
		},
		{
			name: "custom authorized keys",
			cfg: SSHConfig{
				AuthorizedKeys: "/custom/authorized_keys",
			},
			isServer: true,
			expected: SSHConfig{
				Dir:            defaultDir,
				PrivateKey:     defaultPrivateKey,
				AuthorizedKeys: "/custom/authorized_keys",
			},
		},
		{
			name: "custom known hosts",
			cfg: SSHConfig{
				KnownHosts: "/custom/known_hosts",
			},
			isServer: false,
			expected: SSHConfig{
				Dir:        defaultDir,
				PrivateKey: defaultPrivateKey,
				KnownHosts: "/custom/known_hosts",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			SetupSSHPaths(&cfg, tt.isServer)

			if cfg.Dir != tt.expected.Dir {
				t.Errorf("Expected Dir %s, got %s", tt.expected.Dir, cfg.Dir)
			}
			if cfg.PrivateKey != tt.expected.PrivateKey {
				t.Errorf("Expected PrivateKey %s, got %s", tt.expected.PrivateKey, cfg.PrivateKey)
			}
			if tt.isServer && cfg.AuthorizedKeys != tt.expected.AuthorizedKeys {
				t.Errorf("Expected AuthorizedKeys %s, got %s", tt.expected.AuthorizedKeys, cfg.AuthorizedKeys)
			}
			if !tt.isServer && cfg.KnownHosts != tt.expected.KnownHosts {
				t.Errorf("Expected KnownHosts %s, got %s", tt.expected.KnownHosts, cfg.KnownHosts)
			}
		})
	}
}

func TestConfigStructFields(t *testing.T) {
	// Test that all config structs can be instantiated
	_ = CommonConfig{
		LogLevel:          "debug",
		LogFormat:         "json",
		IdleTimeout:       30 * time.Second,
		ReconnectInterval: 5 * time.Second,
		TCPBufSize:        65536,
		UDPSockBuf:        8388608,
		SSH: SSHConfig{
			Dir:            "/test/.ssh",
			PrivateKey:     "/test/.ssh/id_rsa",
			AuthorizedKeys: "/test/.ssh/authorized_keys",
			KnownHosts:     "/test/.ssh/known_hosts",
		},
	}

	_ = ServerConfig{
		CommonConfig:     NewDefaultCommonConfig(),
		ListenAddr:       ":7000",
		Outbound:         "eth0",
		ProxyDialTimeout: 15 * time.Second,
		TUN: TUNServerConfig{
			Name:      "tun1",
			IP:        "10.0.1.1",
			Netmask:   "255.255.255.0",
			IPv6:      "fd00::1/64",
			MTU:       1400,
			AutoRoute: false,
		},
	}

	_ = ClientConfig{
		CommonConfig: NewDefaultCommonConfig(),
		Mode:         "tun",
		ListenAddr:   "127.0.0.1:1081",
		ServerAddr:   "server.example.com:6000",
		SSHTimeout:   60 * time.Second,
		TUN: TUNClientConfig{
			Name:      "tun1",
			MTU:       1400,
			Routes:    "192.168.0.0/16",
			AutoRoute: false,
		},
	}
}
