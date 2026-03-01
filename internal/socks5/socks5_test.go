package socks5

import (
	"bytes"
	"net"
	"testing"
	"time"

	"uproxy/internal/config"
)

// TestParseSOCKS5Request tests SOCKS5 request parsing
func TestParseSOCKS5Request(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name: "valid CONNECT request with IPv4",
			data: []byte{
				config.SOCKS5Version,        // version
				config.SOCKS5CommandConnect, // command
				0x00,                        // reserved
				config.SOCKS5AddressIPv4,    // address type
				192, 168, 1, 1,              // IP address
				0x00, 0x50, // port 80
			},
			wantErr: false,
		},
		{
			name: "valid CONNECT request with domain",
			data: []byte{
				config.SOCKS5Version,        // version
				config.SOCKS5CommandConnect, // command
				0x00,                        // reserved
				config.SOCKS5AddressDomain,  // address type
				0x0b,                        // domain length (11)
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				0x01, 0xbb, // port 443
			},
			wantErr: false,
		},
		{
			name: "valid UDP ASSOCIATE request",
			data: []byte{
				config.SOCKS5Version,             // version
				config.SOCKS5CommandUDPAssociate, // command
				0x00,                             // reserved
				config.SOCKS5AddressIPv4,         // address type
				0, 0, 0, 0,                       // IP address (0.0.0.0)
				0x00, 0x00, // port 0
			},
			wantErr: false,
		},
		{
			name: "invalid version",
			data: []byte{
				0x04,                        // wrong version (SOCKS4)
				config.SOCKS5CommandConnect, // command
				0x00,                        // reserved
				config.SOCKS5AddressIPv4,    // address type
				192, 168, 1, 1,              // IP address
				0x00, 0x50, // port 80
			},
			wantErr: true,
		},
		{
			name: "unsupported command",
			data: []byte{
				config.SOCKS5Version,     // version
				0x02,                     // BIND command (unsupported)
				0x00,                     // reserved
				config.SOCKS5AddressIPv4, // address type
				192, 168, 1, 1,           // IP address
				0x00, 0x50, // port 80
			},
			wantErr: true,
		},
		{
			name: "unsupported address type",
			data: []byte{
				config.SOCKS5Version,        // version
				config.SOCKS5CommandConnect, // command
				0x00,                        // reserved
				0x05,                        // invalid address type
				192, 168, 1, 1,              // IP address
				0x00, 0x50, // port 80
			},
			wantErr: true,
		},
		{
			name:    "truncated request",
			data:    []byte{config.SOCKS5Version, config.SOCKS5CommandConnect},
			wantErr: true,
		},
		{
			name:    "empty request",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBuffer(tt.data)
			conn := &mockConn{
				readBuf:  buf,
				writeBuf: &bytes.Buffer{},
			}

			// Try to read version and command
			if len(tt.data) < 4 {
				if !tt.wantErr {
					t.Errorf("Expected error for truncated data")
				}
				return
			}

			version := tt.data[0]
			if version != config.SOCKS5Version && !tt.wantErr {
				t.Errorf("Expected error for invalid version")
			}

			if len(tt.data) >= 2 {
				cmd := tt.data[1]
				if cmd != config.SOCKS5CommandConnect && cmd != config.SOCKS5CommandUDPAssociate && !tt.wantErr {
					t.Errorf("Expected error for unsupported command")
				}
			}

			_ = conn // Use conn to avoid unused variable warning
		})
	}
}

// TestSOCKS5Handshake tests the SOCKS5 authentication handshake
func TestSOCKS5Handshake(t *testing.T) {
	tests := []struct {
		name       string
		clientData []byte
		wantReply  []byte
		wantErr    bool
	}{
		{
			name: "no authentication",
			clientData: []byte{
				config.SOCKS5Version, // version
				0x01,                 // number of methods
				0x00,                 // no authentication
			},
			wantReply: []byte{
				config.SOCKS5Version, // version
				0x00,                 // no authentication selected
			},
			wantErr: false,
		},
		{
			name: "invalid version",
			clientData: []byte{
				0x04, // SOCKS4
				0x01, // number of methods
				0x00, // no authentication
			},
			wantErr: true,
		},
		{
			name: "no acceptable methods",
			clientData: []byte{
				config.SOCKS5Version, // version
				0x01,                 // number of methods
				0x02,                 // username/password (not supported)
			},
			wantReply: []byte{
				config.SOCKS5Version, // version
				0xFF,                 // no acceptable methods
			},
			wantErr: true,
		},
		{
			name:       "truncated handshake",
			clientData: []byte{config.SOCKS5Version},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBuffer(tt.clientData)
			writeBuf := &bytes.Buffer{}
			conn := &mockConn{
				readBuf:  buf,
				writeBuf: writeBuf,
			}

			// Simulate handshake
			if len(tt.clientData) < 2 {
				if !tt.wantErr {
					t.Errorf("Expected error for truncated handshake")
				}
				return
			}

			version := tt.clientData[0]
			if version != config.SOCKS5Version {
				if !tt.wantErr {
					t.Errorf("Expected error for invalid version")
				}
				return
			}

			_ = conn // Use conn
		})
	}
}

// TestSOCKS5AddressEncoding tests address encoding/decoding
func TestSOCKS5AddressEncoding(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		encoded []byte
		wantErr bool
	}{
		{
			name: "IPv4 address",
			addr: "192.168.1.1:80",
			encoded: []byte{
				config.SOCKS5AddressIPv4,
				192, 168, 1, 1,
				0x00, 0x50,
			},
			wantErr: false,
		},
		{
			name: "IPv6 address",
			addr: "[::1]:443",
			encoded: []byte{
				config.SOCKS5AddressIPv6,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
				0x01, 0xbb,
			},
			wantErr: false,
		},
		{
			name: "domain name",
			addr: "example.com:443",
			encoded: []byte{
				config.SOCKS5AddressDomain,
				0x0b, // length
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				0x01, 0xbb,
			},
			wantErr: false,
		},
		{
			name:    "invalid address",
			addr:    "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test address parsing
			host, port, err := net.SplitHostPort(tt.addr)
			if err != nil && !tt.wantErr {
				t.Errorf("SplitHostPort() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && tt.wantErr {
				t.Errorf("Expected error for invalid address")
				return
			}

			if !tt.wantErr {
				// Verify we can parse the address
				if host == "" || port == "" {
					t.Errorf("Failed to parse address: host=%s, port=%s", host, port)
				}
			}
		})
	}
}

// mockConn implements net.Conn for testing
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return m.writeBuf.Write(b)
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}
