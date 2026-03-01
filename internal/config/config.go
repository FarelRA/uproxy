package config

import (
	"time"

	"uproxy/internal/kcp"
)

// Default constants shared between client and server
// Constants moved to constants.go

// CommonConfig holds configuration shared between client and server
type CommonConfig struct {
	LogLevel  string
	LogFormat string

	IdleTimeout       time.Duration
	ReconnectInterval time.Duration

	TCPBufSize int
	UDPSockBuf int

	KCP KCPConfig
	SSH SSHConfig
}

// KCPConfig holds KCP protocol configuration
type KCPConfig struct {
	NoDelay          int
	Interval         int
	Resend           int
	NoCongestionCtrl int
	SndWnd           int
	RcvWnd           int
	MTU              int
}

// ToKCPConfig converts to internal kcp.Config
func (c *KCPConfig) ToKCPConfig() *kcp.Config {
	return &kcp.Config{
		NoDelay:          c.NoDelay,
		Interval:         c.Interval,
		Resend:           c.Resend,
		NoCongestionCtrl: c.NoCongestionCtrl,
		SndWnd:           c.SndWnd,
		RcvWnd:           c.RcvWnd,
		MTU:              c.MTU,
	}
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
		LogLevel:          DefaultLogLevel,
		LogFormat:         DefaultLogFormat,
		IdleTimeout:       DefaultIdleTimeout,
		ReconnectInterval: DefaultReconnectInterval,
		TCPBufSize:        DefaultTCPBufSize,
		UDPSockBuf:        DefaultUDPSockBuf,
		KCP: KCPConfig{
			NoDelay:          DefaultKCPNoDelay,
			Interval:         DefaultKCPInterval,
			Resend:           DefaultKCPResend,
			NoCongestionCtrl: DefaultKCPNC,
			SndWnd:           DefaultKCPSndWnd,
			RcvWnd:           DefaultKCPRcvWnd,
			MTU:              DefaultKCPMTU,
		},
		SSH: SSHConfig{},
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
		SSHTimeout:   DefaultSSHTimeout,
		TUN: TUNClientConfig{
			Name:      "tun0",
			MTU:       DefaultTUNMTU,
			AutoRoute: true,
		},
	}
}
