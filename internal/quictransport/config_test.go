package quictransport

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestNewQUICConfig(t *testing.T) {
	tests := []struct {
		name string
		opts *QUICConfigOptions
		want *quic.Config
	}{
		{
			name: "nil options uses defaults",
			opts: nil,
			want: &quic.Config{
				MaxIdleTimeout:  DefaultMaxIdleTimeout,
				KeepAlivePeriod: DefaultKeepAlivePeriod,
			},
		},
		{
			name: "custom options",
			opts: &QUICConfigOptions{
				MaxIdleTimeout:  2 * time.Hour,
				KeepAlivePeriod: 1 * time.Minute,
			},
			want: &quic.Config{
				MaxIdleTimeout:  2 * time.Hour,
				KeepAlivePeriod: 1 * time.Minute,
			},
		},
		{
			name: "zero values are passed through",
			opts: &QUICConfigOptions{},
			want: &quic.Config{
				MaxIdleTimeout:  0,
				KeepAlivePeriod: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewQUICConfig(tt.opts)
			if got.MaxIdleTimeout != tt.want.MaxIdleTimeout {
				t.Errorf("MaxIdleTimeout = %v, want %v", got.MaxIdleTimeout, tt.want.MaxIdleTimeout)
			}
			if got.KeepAlivePeriod != tt.want.KeepAlivePeriod {
				t.Errorf("KeepAlivePeriod = %v, want %v", got.KeepAlivePeriod, tt.want.KeepAlivePeriod)
			}
		})
	}
}

func TestNewClientTLSConfig(t *testing.T) {
	// Create a dummy certificate for testing
	cert := tls.Certificate{
		Certificate: [][]byte{{0x01, 0x02, 0x03}},
	}

	verifyCallbackCalled := false
	verifyCallback := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		verifyCallbackCalled = true
		return nil
	}

	config, err := NewClientTLSConfig(cert, verifyCallback)
	if err != nil {
		t.Fatalf("NewClientTLSConfig() error = %v", err)
	}

	if len(config.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(config.Certificates))
	}

	if config.InsecureSkipVerify != true {
		t.Error("Expected InsecureSkipVerify to be true")
	}

	if config.VerifyPeerCertificate == nil {
		t.Error("Expected VerifyPeerCertificate to be set")
	}

	if config.MinVersion != tls.VersionTLS13 {
		t.Errorf("Expected MinVersion TLS 1.3, got %v", config.MinVersion)
	}

	if len(config.NextProtos) != 1 || config.NextProtos[0] != NextProtoUProxy {
		t.Errorf("Expected NextProtos [%s], got %v", NextProtoUProxy, config.NextProtos)
	}

	// Test that callback is actually called
	if config.VerifyPeerCertificate != nil {
		config.VerifyPeerCertificate([][]byte{{0x01}}, nil)
		if !verifyCallbackCalled {
			t.Error("VerifyPeerCertificate callback was not called")
		}
	}
}

func TestNewClientTLSConfig_Errors(t *testing.T) {
	tests := []struct {
		name     string
		cert     tls.Certificate
		callback func([][]byte, [][]*x509.Certificate) error
		wantErr  error
	}{
		{
			name:     "empty certificate",
			cert:     tls.Certificate{},
			callback: func([][]byte, [][]*x509.Certificate) error { return nil },
			wantErr:  ErrNoCertificate,
		},
		{
			name:     "nil callback",
			cert:     tls.Certificate{Certificate: [][]byte{{0x01}}},
			callback: nil,
			wantErr:  ErrNoVerifyCallback,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClientTLSConfig(tt.cert, tt.callback)
			if err != tt.wantErr {
				t.Errorf("NewClientTLSConfig() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewServerTLSConfig(t *testing.T) {
	cert := tls.Certificate{
		Certificate: [][]byte{{0x01, 0x02, 0x03}},
	}

	verifyCallbackCalled := false
	verifyCallback := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		verifyCallbackCalled = true
		return nil
	}

	config, err := NewServerTLSConfig(cert, verifyCallback)
	if err != nil {
		t.Fatalf("NewServerTLSConfig() error = %v", err)
	}

	if len(config.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(config.Certificates))
	}

	if config.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("Expected ClientAuth RequireAnyClientCert, got %v", config.ClientAuth)
	}

	if config.VerifyPeerCertificate == nil {
		t.Error("Expected VerifyPeerCertificate to be set")
	}

	if config.MinVersion != tls.VersionTLS13 {
		t.Errorf("Expected MinVersion TLS 1.3, got %v", config.MinVersion)
	}

	if len(config.NextProtos) != 1 || config.NextProtos[0] != NextProtoUProxy {
		t.Errorf("Expected NextProtos [%s], got %v", NextProtoUProxy, config.NextProtos)
	}

	// Test that callback is actually called
	if config.VerifyPeerCertificate != nil {
		config.VerifyPeerCertificate([][]byte{{0x01}}, nil)
		if !verifyCallbackCalled {
			t.Error("VerifyPeerCertificate callback was not called")
		}
	}
}

func TestNewServerTLSConfig_Errors(t *testing.T) {
	tests := []struct {
		name     string
		cert     tls.Certificate
		callback func([][]byte, [][]*x509.Certificate) error
		wantErr  error
	}{
		{
			name:     "empty certificate",
			cert:     tls.Certificate{},
			callback: func([][]byte, [][]*x509.Certificate) error { return nil },
			wantErr:  ErrNoCertificate,
		},
		{
			name:     "nil callback",
			cert:     tls.Certificate{Certificate: [][]byte{{0x01}}},
			callback: nil,
			wantErr:  ErrNoVerifyCallback,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServerTLSConfig(tt.cert, tt.callback)
			if err != tt.wantErr {
				t.Errorf("NewServerTLSConfig() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateQUICConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *quic.Config
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "valid config",
			config: &quic.Config{
				MaxIdleTimeout:  1 * time.Hour,
				KeepAlivePeriod: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "zero idle timeout",
			config: &quic.Config{
				MaxIdleTimeout:  0,
				KeepAlivePeriod: 30 * time.Second,
			},
			wantErr: false, // Zero is valid (means no timeout)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateQUICConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateQUICConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTLSConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   *tls.Config
		isServer bool
		wantErr  bool
	}{
		{
			name:     "nil config - client",
			config:   nil,
			isServer: false,
			wantErr:  true,
		},
		{
			name:     "nil config - server",
			config:   nil,
			isServer: true,
			wantErr:  true,
		},
		{
			name:     "empty client config",
			config:   &tls.Config{},
			isServer: false,
			wantErr:  true,
		},
		{
			name:     "empty server config",
			config:   &tls.Config{},
			isServer: true,
			wantErr:  true,
		},
		{
			name: "missing certificates",
			config: &tls.Config{
				NextProtos: []string{"uproxy"},
			},
			isServer: false,
			wantErr:  true,
		},
		{
			name: "missing ALPN protocols",
			config: &tls.Config{
				Certificates: []tls.Certificate{
					{Certificate: [][]byte{{0x01}}},
				},
			},
			isServer: false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTLSConfig(tt.config, tt.isServer)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTLSConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
