package config

import "time"

// SOCKS5 Protocol Constants
const (
	SOCKS5Version             = 0x05
	SOCKS5AuthNone            = 0x00
	SOCKS5CommandConnect      = 0x01
	SOCKS5CommandBind         = 0x02
	SOCKS5CommandUDPAssociate = 0x03
	SOCKS5AddressIPv4         = 0x01
	SOCKS5AddressDomain       = 0x03
	SOCKS5AddressIPv6         = 0x04
	SOCKS5ReplySuccess        = 0x00
	SOCKS5ReplyGeneralFailure = 0x01
)

// Buffer and Network Constants
const (
	DefaultBufferSize = 2048
	DefaultTCPBufSize = 32768
	DefaultUDPSockBuf = 4194304
	MaxUDPPacketSize  = 65507
)

// Timing Constants
const (
	DefaultRetryDelay          = 100 * time.Millisecond
	MaxRetryAttempts           = 150
	DefaultReconnectRetryWait  = 5 * time.Second
	DefaultReconnectInterval   = 5 * time.Second
	DefaultIdleTimeout         = 0 * time.Second
	DefaultSSHTimeout          = 30 * time.Second
	DefaultProxyDialTimeout    = 10 * time.Second
	ConnectivityCheckInterval  = 500 * time.Millisecond
	TUNDeviceCheckInterval     = 100 * time.Millisecond
	TUNDeviceMaxAttempts       = 30
	DefaultShutdownGracePeriod = 5 * time.Second
	SSHConnectionWaitInterval  = 1 * time.Second
	DefaultUDPTimeout          = 5 * time.Minute
	DefaultTelemetryInterval   = 30 * time.Second
	MaxIPAllocationAttempts    = 500
)

// IP and Network Constants
const (
	IPv4HeaderMinLength = 20
	IPv6HeaderLength    = 40
	IPv4Version         = 4
	IPv6Version         = 6
)

// Logging Constants
const (
	DefaultLogLevel  = "info"
	DefaultLogFormat = "text"
)

// KCP Protocol Constants
const (
	DefaultKCPNoDelay   = 1
	DefaultKCPInterval  = 10
	DefaultKCPResend    = 2
	DefaultKCPNC        = 1
	DefaultKCPSndWnd    = 1024
	DefaultKCPRcvWnd    = 1024
	DefaultKCPMTU       = 1350
	DefaultKCPDeadLink  = 0 // 0 means disabled
	DefaultKCPStreamBuf = 4194304
)

// TUN Device Constants
const (
	DefaultTUNMTU           = 1500
	DefaultServerTUNIP      = "10.0.0.1"
	DefaultServerTUNNetmask = "255.255.255.0"
	DefaultServerTUNIPv6    = "fd00::1/64"
)

// SSH Configuration Constants
const (
	SSHDirName            = ".ssh"
	SSHPrivateKeyEd25519  = "id_ed25519"
	SSHPrivateKeyRSA      = "id_rsa"
	SSHAuthorizedKeysFile = "authorized_keys"
	SSHKnownHostsFile     = "known_hosts"
	DefaultSSHUser        = "proxy"
)

// Network Address Constants
const (
	LocalhostIPv4                   = "127.0.0.1"
	DevTTYPath                      = "/dev/tty"
	DefaultMaxConcurrentConnections = 1000
)
