package quictransport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	// DefaultMaxIdleTimeout is the default maximum idle time before a connection is closed
	DefaultMaxIdleTimeout = 1 * time.Hour

	// DefaultKeepAlivePeriod is the default interval for sending keep-alive packets
	DefaultKeepAlivePeriod = 30 * time.Second

	// DefaultMaxIncomingStreams is the default maximum number of concurrent incoming streams (0 = unlimited)
	DefaultMaxIncomingStreams = 0

	// DefaultMaxIncomingUniStreams is the default maximum number of concurrent incoming unidirectional streams
	DefaultMaxIncomingUniStreams = 0

	// NextProtoUProxy is the ALPN protocol identifier for uproxy
	NextProtoUProxy = "uproxy"
)

var (
	// ErrNoCertificate is returned when no certificate is provided
	ErrNoCertificate = errors.New("no certificate provided")
	// ErrNoVerifyCallback is returned when no verification callback is provided
	ErrNoVerifyCallback = errors.New("no verification callback provided")
)

// QUICConfigOptions contains options for creating a QUIC configuration.
type QUICConfigOptions struct {
	HandshakeIdleTimeout           time.Duration
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
	MaxIncomingStreams             int64
	MaxIncomingUniStreams          int64
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	InitialPacketSize              uint16
	DisablePathMTUDiscovery        bool
	Enable0RTT                     bool
	EnableDatagrams                bool
}

// DefaultQUICConfigOptions returns the default QUIC configuration options.
func DefaultQUICConfigOptions() *QUICConfigOptions {
	return &QUICConfigOptions{
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIdleTimeout:                 DefaultMaxIdleTimeout,
		KeepAlivePeriod:                DefaultKeepAlivePeriod,
		MaxIncomingStreams:             DefaultMaxIncomingStreams,
		MaxIncomingUniStreams:          DefaultMaxIncomingUniStreams,
		InitialStreamReceiveWindow:     0, // Use QUIC default
		MaxStreamReceiveWindow:         0, // Use QUIC default
		InitialConnectionReceiveWindow: 0, // Use QUIC default
		MaxConnectionReceiveWindow:     0, // Use QUIC default
		InitialPacketSize:              1280,
		DisablePathMTUDiscovery:        false,
		Enable0RTT:                     false,
		EnableDatagrams:                true,
	}
}

// NewQUICConfig creates a new QUIC configuration with the provided options.
// If opts is nil, default options are used.
func NewQUICConfig(opts *QUICConfigOptions) *quic.Config {
	if opts == nil {
		opts = DefaultQUICConfigOptions()
	}

	config := &quic.Config{
		HandshakeIdleTimeout:           opts.HandshakeIdleTimeout,
		MaxIdleTimeout:                 opts.MaxIdleTimeout,
		MaxIncomingStreams:             opts.MaxIncomingStreams,
		MaxIncomingUniStreams:          opts.MaxIncomingUniStreams,
		InitialStreamReceiveWindow:     opts.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         opts.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: opts.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     opts.MaxConnectionReceiveWindow,
		KeepAlivePeriod:                opts.KeepAlivePeriod,
		InitialPacketSize:              opts.InitialPacketSize,
		DisablePathMTUDiscovery:        opts.DisablePathMTUDiscovery,
		Allow0RTT:                      opts.Enable0RTT,
		EnableDatagrams:                opts.EnableDatagrams,
	}

	if opts.MaxIncomingStreams > 0 {
		config.MaxIncomingStreams = opts.MaxIncomingStreams
	}

	if opts.MaxIncomingUniStreams > 0 {
		config.MaxIncomingUniStreams = opts.MaxIncomingUniStreams
	}

	if opts.InitialStreamReceiveWindow > 0 {
		config.InitialStreamReceiveWindow = opts.InitialStreamReceiveWindow
	}

	if opts.MaxStreamReceiveWindow > 0 {
		config.MaxStreamReceiveWindow = opts.MaxStreamReceiveWindow
	}

	if opts.InitialConnectionReceiveWindow > 0 {
		config.InitialConnectionReceiveWindow = opts.InitialConnectionReceiveWindow
	}

	if opts.MaxConnectionReceiveWindow > 0 {
		config.MaxConnectionReceiveWindow = opts.MaxConnectionReceiveWindow
	}

	return config
}

// NewClientTLSConfig creates a TLS configuration for a QUIC client.
// The certificate is the client's certificate (generated from SSH key).
// The verifyCallback is called to verify the server's certificate.
func NewClientTLSConfig(certificate tls.Certificate, verifyCallback func([][]byte, [][]*x509.Certificate) error) (*tls.Config, error) {
	if len(certificate.Certificate) == 0 {
		return nil, ErrNoCertificate
	}

	if verifyCallback == nil {
		return nil, ErrNoVerifyCallback
	}

	return &tls.Config{
		Certificates:          []tls.Certificate{certificate},
		NextProtos:            []string{NextProtoUProxy},
		ClientAuth:            tls.NoClientCert,
		VerifyPeerCertificate: verifyCallback,
		InsecureSkipVerify:    true, // Required when using custom VerifyPeerCertificate
		MinVersion:            tls.VersionTLS13,
	}, nil
}

// NewServerTLSConfig creates a TLS configuration for a QUIC server.
// The certificate is the server's certificate (generated from SSH key).
// The verifyCallback is called to verify each client's certificate.
func NewServerTLSConfig(certificate tls.Certificate, verifyCallback func([][]byte, [][]*x509.Certificate) error) (*tls.Config, error) {
	if len(certificate.Certificate) == 0 {
		return nil, ErrNoCertificate
	}

	if verifyCallback == nil {
		return nil, ErrNoVerifyCallback
	}

	return &tls.Config{
		Certificates:          []tls.Certificate{certificate},
		NextProtos:            []string{NextProtoUProxy},
		ClientAuth:            tls.RequireAnyClientCert, // Require client certificates for mTLS
		VerifyPeerCertificate: verifyCallback,
		MinVersion:            tls.VersionTLS13,
	}, nil
}

// ValidateQUICConfig validates a QUIC configuration and returns an error if invalid.
func ValidateQUICConfig(config *quic.Config) error {
	if config == nil {
		return errors.New("QUIC config is nil")
	}

	if config.MaxIdleTimeout < 0 {
		return fmt.Errorf("MaxIdleTimeout must be non-negative, got %v", config.MaxIdleTimeout)
	}

	if config.MaxIdleTimeout > 0 && config.MaxIdleTimeout < 10*time.Second {
		return fmt.Errorf("MaxIdleTimeout is too short (<%v), may cause frequent disconnections", 10*time.Second)
	}

	if config.KeepAlivePeriod < 0 {
		return fmt.Errorf("KeepAlivePeriod must be non-negative, got %v", config.KeepAlivePeriod)
	}

	if config.KeepAlivePeriod > 0 && config.KeepAlivePeriod < 5*time.Second {
		return fmt.Errorf("KeepAlivePeriod is too short (<%v), may cause excessive traffic", 5*time.Second)
	}

	if config.MaxIncomingStreams < 0 {
		return fmt.Errorf("MaxIncomingStreams must be non-negative, got %d", config.MaxIncomingStreams)
	}

	if config.MaxIncomingUniStreams < 0 {
		return fmt.Errorf("MaxIncomingUniStreams must be non-negative, got %d", config.MaxIncomingUniStreams)
	}

	return nil
}

// ValidateTLSConfig validates a TLS configuration and returns an error if invalid.
func ValidateTLSConfig(config *tls.Config, isServer bool) error {
	if config == nil {
		return errors.New("TLS config is nil")
	}

	if len(config.Certificates) == 0 {
		return errors.New("no certificates configured")
	}

	if len(config.NextProtos) == 0 {
		return errors.New("no ALPN protocols configured")
	}

	if config.VerifyPeerCertificate == nil {
		return errors.New("no peer certificate verification callback configured")
	}

	if isServer {
		if config.ClientAuth != tls.RequireAnyClientCert {
			return fmt.Errorf("server must require client certificates for mTLS, got ClientAuth=%v", config.ClientAuth)
		}
	} else {
		if !config.InsecureSkipVerify {
			return errors.New("client must set InsecureSkipVerify=true when using custom verification")
		}
	}

	if config.MinVersion < tls.VersionTLS13 {
		return fmt.Errorf("minimum TLS version must be 1.3, got %v", config.MinVersion)
	}

	return nil
}
