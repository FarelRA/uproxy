// Package config provides configuration structures and default values for uproxy.
// It includes client and server configuration options and shared constants
// used throughout the application.
package config

import (
	"time"
)

// Default constants shared between client and server
// Constants moved to constants.go

// CommonConfig holds configuration shared between client and server
type CommonConfig struct {
	LogLevel  string
	LogFormat string

	IdleTimeout time.Duration

	TCPBufSize int

	SSH  SSHConfig
	QUIC QUICConfig
}

// QUICConfig holds QUIC protocol configuration
type QUICConfig struct {
	HandshakeIdleTimeout           time.Duration
	MaxIdleTimeout                 time.Duration
	MaxIncomingStreams             int64
	MaxIncomingUniStreams          int64
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	KeepAlivePeriod                time.Duration
	InitialPacketSize              uint16
	DisablePathMTUDiscovery        bool
	Enable0RTT                     bool
	EnableDatagrams                bool
}

// SSHConfig holds SSH configuration paths
type SSHConfig struct {
	Dir            string
	PrivateKey     string
	AuthorizedKeys string // Server only
	KnownHosts     string // Client only
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	CommonConfig

	ListenAddr string
	Outbound   string

	ProxyDialTimeout time.Duration

	TUN TUNServerConfig
}

// TUNServerConfig holds server TUN configuration
type TUNServerConfig struct {
	Name      string
	IP        string
	Netmask   string
	IPv6      string
	MTU       int
	AutoRoute bool
}

// ClientConfig holds client-specific configuration
type ClientConfig struct {
	CommonConfig

	Mode       string
	ListenAddr string
	ServerAddr string
	BindAddr   string // UDP bind address for QUIC connection

	SSHTimeout time.Duration

	TUN TUNClientConfig
}

// TUNClientConfig holds client TUN configuration
type TUNClientConfig struct {
	Name      string
	MTU       int
	Routes    string
	AutoRoute bool
}

// NewDefaultCommonConfig returns a CommonConfig with default values
func NewDefaultCommonConfig() CommonConfig {
	return CommonConfig{
		LogLevel:    DefaultLogLevel,
		LogFormat:   DefaultLogFormat,
		IdleTimeout: DefaultIdleTimeout,
		TCPBufSize:  DefaultTCPBufSize,
		SSH:         SSHConfig{},
		QUIC: QUICConfig{
			HandshakeIdleTimeout:           DefaultQUICHandshakeIdleTimeout,
			MaxIdleTimeout:                 DefaultQUICMaxIdleTimeout,
			MaxIncomingStreams:             DefaultQUICMaxIncomingStreams,
			MaxIncomingUniStreams:          DefaultQUICMaxIncomingUniStreams,
			InitialStreamReceiveWindow:     DefaultQUICInitialStreamReceiveWindow,
			MaxStreamReceiveWindow:         DefaultQUICMaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: DefaultQUICInitialConnectionReceiveWindow,
			MaxConnectionReceiveWindow:     DefaultQUICMaxConnectionReceiveWindow,
			KeepAlivePeriod:                DefaultQUICKeepAlivePeriod,
			InitialPacketSize:              DefaultQUICInitialPacketSize,
			DisablePathMTUDiscovery:        DefaultQUICDisablePathMTUDiscovery,
			Enable0RTT:                     DefaultQUICEnable0RTT,
			EnableDatagrams:                DefaultQUICEnableDatagrams,
		},
	}
}

// NewDefaultServerConfig returns a ServerConfig with default values
func NewDefaultServerConfig() ServerConfig {
	return ServerConfig{
		CommonConfig:     NewDefaultCommonConfig(),
		ListenAddr:       ":6000",
		ProxyDialTimeout: DefaultProxyDialTimeout,
		TUN: TUNServerConfig{
			Name:      "tun0",
			IP:        DefaultServerTUNIP,
			Netmask:   DefaultServerTUNNetmask,
			IPv6:      DefaultServerTUNIPv6,
			MTU:       DefaultTUNMTU,
			AutoRoute: true,
		},
	}
}

// NewDefaultClientConfig returns a ClientConfig with default values
func NewDefaultClientConfig() ClientConfig {
	return ClientConfig{
		CommonConfig: NewDefaultCommonConfig(),
		Mode:         "auto",
		ListenAddr:   "127.0.0.1:1080",
		BindAddr:     DefaultClientBindAddr,
		SSHTimeout:   DefaultSSHTimeout,
		TUN: TUNClientConfig{
			Name:      "tun0",
			MTU:       DefaultTUNMTU,
			AutoRoute: true,
		},
	}
}
