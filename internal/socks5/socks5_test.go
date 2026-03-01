package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"uproxy/internal/config"
)

// TestPerformSOCKS5Handshake tests the SOCKS5 handshake
func TestPerformSOCKS5Handshake(t *testing.T) {
	tests := []struct {
		name       string
		clientData []byte
		wantErr    bool
	}{
		{
			name: "valid no auth handshake",
			clientData: []byte{
				0x05, // version
				0x01, // 1 method
				0x00, // no auth
			},
			wantErr: false,
		},
		{
			name: "invalid version",
			clientData: []byte{
				0x04, // SOCKS4
				0x01,
				0x00,
			},
			wantErr: true,
		},
		{
			name:       "truncated handshake",
			clientData: []byte{0x05},
			wantErr:    true,
		},
		{
			name: "valid with multiple methods",
			clientData: []byte{
				0x05,       // version
				0x02,       // 2 methods
				0x00, 0x02, // no auth, username/password
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{
				readBuf:  bytes.NewBuffer(tt.clientData),
				writeBuf: &bytes.Buffer{},
			}

			err := performSOCKS5Handshake(conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("performSOCKS5Handshake() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				// Check response
				resp := conn.writeBuf.Bytes()
				if len(resp) != 2 || resp[0] != 0x05 || resp[1] != 0x00 {
					t.Errorf("Invalid handshake response: %v", resp)
				}
			}
		})
	}
}

// TestParseSOCKS5Request tests SOCKS5 request parsing
func TestParseSOCKS5Request(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantCmd    byte
		wantTarget string
		wantErr    bool
	}{
		{
			name: "valid CONNECT IPv4",
			data: []byte{
				0x05,                        // version
				config.SOCKS5CommandConnect, // command
				0x00,                        // reserved
				config.SOCKS5AddressIPv4,    // address type
				192, 168, 1, 1,              // IP
				0x00, 0x50, // port 80
			},
			wantCmd:    config.SOCKS5CommandConnect,
			wantTarget: "192.168.1.1:80",
			wantErr:    false,
		},
		{
			name: "valid CONNECT domain",
			data: []byte{
				0x05,                        // version
				config.SOCKS5CommandConnect, // command
				0x00,                        // reserved
				config.SOCKS5AddressDomain,  // address type
				0x0b,                        // length 11
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				0x01, 0xbb, // port 443
			},
			wantCmd:    config.SOCKS5CommandConnect,
			wantTarget: "example.com:443",
			wantErr:    false,
		},
		{
			name: "valid UDP ASSOCIATE",
			data: []byte{
				0x05,                             // version
				config.SOCKS5CommandUDPAssociate, // command
				0x00,                             // reserved
				config.SOCKS5AddressIPv4,         // address type
				0, 0, 0, 0,                       // IP
				0x00, 0x00, // port 0
			},
			wantCmd:    config.SOCKS5CommandUDPAssociate,
			wantTarget: "0.0.0.0:0",
			wantErr:    false,
		},
		{
			name: "valid IPv6",
			data: []byte{
				0x05,                                           // version
				config.SOCKS5CommandConnect,                    // command
				0x00,                                           // reserved
				config.SOCKS5AddressIPv6,                       // address type
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ::1
				0x01, 0xbb, // port 443
			},
			wantCmd:    config.SOCKS5CommandConnect,
			wantTarget: "[::1]:443",
			wantErr:    false,
		},
		{
			name: "invalid version",
			data: []byte{
				0x04,                        // wrong version
				config.SOCKS5CommandConnect, // command
				0x00,                        // reserved
				config.SOCKS5AddressIPv4,    // address type
				192, 168, 1, 1,
				0x00, 0x50,
			},
			wantErr: true,
		},
		{
			name: "invalid address type",
			data: []byte{
				0x05,                        // version
				config.SOCKS5CommandConnect, // command
				0x00,                        // reserved
				0x99,                        // invalid address type
				192, 168, 1, 1,
				0x00, 0x50,
			},
			wantErr: true,
		},
		{
			name:    "truncated request",
			data:    []byte{0x05, 0x01},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{
				readBuf:  bytes.NewBuffer(tt.data),
				writeBuf: &bytes.Buffer{},
			}

			cmd, target, err := parseSOCKS5Request(conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSOCKS5Request() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if cmd != tt.wantCmd {
					t.Errorf("parseSOCKS5Request() cmd = %v, want %v", cmd, tt.wantCmd)
				}
				if target != tt.wantTarget {
					t.Errorf("parseSOCKS5Request() target = %v, want %v", target, tt.wantTarget)
				}
			}
		})
	}
}

// TestHandleConnectCommand tests TCP CONNECT handling
func TestHandleConnectCommand(t *testing.T) {
	t.Run("successful connect", func(t *testing.T) {
		conn := &mockConn{
			readBuf:  &bytes.Buffer{},
			writeBuf: &bytes.Buffer{},
		}

		remoteConn := &mockConn{
			readBuf:  bytes.NewBuffer([]byte("response")),
			writeBuf: &bytes.Buffer{},
		}

		dialTCP := func(addr string) (net.Conn, error) {
			return remoteConn, nil
		}

		handleConnectCommand(conn, "example.com:80", "127.0.0.1:12345", dialTCP)

		// Check success response
		resp := conn.writeBuf.Bytes()
		if len(resp) < 10 || resp[0] != 0x05 || resp[1] != 0x00 {
			t.Errorf("Invalid success response: %v", resp)
		}
	})

	t.Run("failed connect", func(t *testing.T) {
		conn := &mockConn{
			readBuf:  &bytes.Buffer{},
			writeBuf: &bytes.Buffer{},
		}

		dialTCP := func(addr string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}

		handleConnectCommand(conn, "example.com:80", "127.0.0.1:12345", dialTCP)

		// Check error response
		resp := conn.writeBuf.Bytes()
		if len(resp) < 10 || resp[0] != 0x05 || resp[1] != 0x05 {
			t.Errorf("Invalid error response: %v", resp)
		}
	})
}

// TestHandleUDPAssociate tests UDP ASSOCIATE handling
func TestHandleUDPAssociate(t *testing.T) {
	t.Run("successful UDP associate IPv4", func(t *testing.T) {
		conn := &mockConn{
			readBuf:  &bytes.Buffer{},
			writeBuf: &bytes.Buffer{},
		}

		udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}
		closer := &mockCloser{}

		dialUDP := func() (net.Addr, io.Closer, error) {
			return udpAddr, closer, nil
		}

		go handleUDPAssociate(conn, "127.0.0.1:12345", dialUDP)
		time.Sleep(10 * time.Millisecond)

		// Check response
		resp := conn.writeBuf.Bytes()
		if len(resp) < 10 || resp[0] != 0x05 || resp[1] != 0x00 {
			t.Errorf("Invalid UDP associate response: %v", resp)
		}

		conn.Close()
	})

	t.Run("successful UDP associate IPv6", func(t *testing.T) {
		conn := &mockConn{
			readBuf:  &bytes.Buffer{},
			writeBuf: &bytes.Buffer{},
		}

		udpAddr := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5000}
		closer := &mockCloser{}

		dialUDP := func() (net.Addr, io.Closer, error) {
			return udpAddr, closer, nil
		}

		go handleUDPAssociate(conn, "127.0.0.1:12345", dialUDP)
		time.Sleep(10 * time.Millisecond)

		// Check response
		resp := conn.writeBuf.Bytes()
		if len(resp) < 22 || resp[0] != 0x05 || resp[1] != 0x00 || resp[3] != 0x04 {
			t.Errorf("Invalid UDP associate IPv6 response: %v", resp)
		}

		conn.Close()
	})

	t.Run("failed UDP associate", func(t *testing.T) {
		conn := &mockConn{
			readBuf:  &bytes.Buffer{},
			writeBuf: &bytes.Buffer{},
		}

		dialUDP := func() (net.Addr, io.Closer, error) {
			return nil, nil, errors.New("bind failed")
		}

		handleUDPAssociate(conn, "127.0.0.1:12345", dialUDP)

		// Check error response
		resp := conn.writeBuf.Bytes()
		if len(resp) < 10 || resp[0] != 0x05 || resp[1] != 0x05 {
			t.Errorf("Invalid error response: %v", resp)
		}
	})
}

// TestBufferPool tests UDP buffer pool
func TestBufferPool(t *testing.T) {
	buf1 := getUDPBuffer()
	if buf1 == nil || len(*buf1) != UDPBufSize {
		t.Errorf("getUDPBuffer() returned invalid buffer")
	}

	putUDPBuffer(buf1)

	buf2 := getUDPBuffer()
	if buf2 == nil || len(*buf2) != UDPBufSize {
		t.Errorf("getUDPBuffer() after put returned invalid buffer")
	}

	// Test putting nil buffer
	putUDPBuffer(nil)

	// Test putting wrong size buffer
	wrongSize := make([]byte, 100)
	putUDPBuffer(&wrongSize)
}

// TestWriteReadTargetHeader tests target header encoding/decoding
func TestWriteReadTargetHeader(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{"short target", "example.com:80"},
		{"long target", "very-long-domain-name-for-testing.example.com:443"},
		{"IPv4 target", "192.168.1.1:8080"},
		{"IPv6 target", "[::1]:9000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}

			err := WriteTargetHeader(buf, tt.target)
			if err != nil {
				t.Errorf("WriteTargetHeader() error = %v", err)
				return
			}

			target, err := ReadTargetHeader(buf)
			if err != nil {
				t.Errorf("ReadTargetHeader() error = %v", err)
				return
			}

			if target != tt.target {
				t.Errorf("ReadTargetHeader() = %v, want %v", target, tt.target)
			}
		})
	}

	t.Run("read error - truncated length", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{0x00})
		_, err := ReadTargetHeader(buf)
		if err == nil {
			t.Error("ReadTargetHeader() expected error for truncated length")
		}
	})

	t.Run("read error - truncated data", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{0x00, 0x0a, 'a', 'b'})
		_, err := ReadTargetHeader(buf)
		if err == nil {
			t.Error("ReadTargetHeader() expected error for truncated data")
		}
	})
}

// TestParseSOCKS5UDPHeader tests UDP header parsing
func TestParseSOCKS5UDPHeader(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantTarget  string
		wantPayload []byte
		wantErr     bool
	}{
		{
			name: "valid IPv4",
			data: []byte{
				0x00, 0x00, 0x00, // RSV, FRAG
				0x01,           // ATYP IPv4
				192, 168, 1, 1, // IP
				0x00, 0x50, // port 80
				'p', 'a', 'y', 'l', 'o', 'a', 'd',
			},
			wantTarget:  "192.168.1.1:80",
			wantPayload: []byte{'p', 'a', 'y', 'l', 'o', 'a', 'd'},
			wantErr:     false,
		},
		{
			name: "valid domain",
			data: []byte{
				0x00, 0x00, 0x00, // RSV, FRAG
				0x03, // ATYP domain
				0x0b, // length 11
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				0x01, 0xbb, // port 443
				'd', 'a', 't', 'a',
			},
			wantTarget:  "example.com:443",
			wantPayload: []byte{'d', 'a', 't', 'a'},
			wantErr:     false,
		},
		{
			name: "valid IPv6",
			data: []byte{
				0x00, 0x00, 0x00, // RSV, FRAG
				0x04,                                           // ATYP IPv6
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // ::1
				0x01, 0xbb, // port 443
				't', 'e', 's', 't',
			},
			wantTarget:  "[::1]:443",
			wantPayload: []byte{'t', 'e', 's', 't'},
			wantErr:     false,
		},
		{
			name:    "too short",
			data:    []byte{0x00, 0x00, 0x00, 0x01},
			wantErr: true,
		},
		{
			name: "fragmentation not supported",
			data: []byte{
				0x00, 0x00, 0x01, // FRAG != 0
				0x01,
				192, 168, 1, 1,
				0x00, 0x50,
			},
			wantErr: true,
		},
		{
			name: "invalid address type",
			data: []byte{
				0x00, 0x00, 0x00,
				0x99, // invalid ATYP
				192, 168, 1, 1,
				0x00, 0x50,
			},
			wantErr: true,
		},
		{
			name: "truncated IPv4",
			data: []byte{
				0x00, 0x00, 0x00,
				0x01,
				192, 168,
			},
			wantErr: true,
		},
		{
			name: "truncated domain",
			data: []byte{
				0x00, 0x00, 0x00,
				0x03,
				0x0a,
				'a', 'b',
			},
			wantErr: true,
		},
		{
			name: "truncated IPv6",
			data: []byte{
				0x00, 0x00, 0x00,
				0x04,
				0, 0, 0, 0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, payload, header, err := parseSOCKS5UDPHeader(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSOCKS5UDPHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if target != tt.wantTarget {
					t.Errorf("parseSOCKS5UDPHeader() target = %v, want %v", target, tt.wantTarget)
				}
				if !bytes.Equal(payload, tt.wantPayload) {
					t.Errorf("parseSOCKS5UDPHeader() payload = %v, want %v", payload, tt.wantPayload)
				}
				if header == nil {
					t.Error("parseSOCKS5UDPHeader() header is nil")
				}
			}
		})
	}
}

// TestHandleSOCKS5Client tests the main client handler
func TestHandleSOCKS5Client(t *testing.T) {
	t.Run("unsupported command", func(t *testing.T) {
		// Handshake + request with BIND command (0x02)
		data := []byte{
			// Handshake
			0x05, 0x01, 0x00,
			// Request
			0x05, 0x02, 0x00, 0x01, // BIND command
			192, 168, 1, 1,
			0x00, 0x50,
		}

		conn := &mockConn{
			readBuf:  bytes.NewBuffer(data),
			writeBuf: &bytes.Buffer{},
		}

		dialTCP := func(addr string) (net.Conn, error) {
			return nil, errors.New("should not be called")
		}

		dialUDP := func() (net.Addr, io.Closer, error) {
			return nil, nil, errors.New("should not be called")
		}

		handleSOCKS5Client(conn, dialTCP, dialUDP)

		// Check that unsupported command response was sent
		resp := conn.writeBuf.Bytes()
		if len(resp) < 12 {
			t.Errorf("Response too short: %v", resp)
			return
		}
		// Skip handshake response (2 bytes), check command response
		if resp[2] != 0x05 || resp[3] != 0x07 {
			t.Errorf("Expected unsupported command error, got: %v", resp[2:])
		}
	})
}

// mockConn implements net.Conn for testing
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.closed {
		return 0, errors.New("connection closed")
	}
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

// mockCloser implements io.Closer for testing
type mockCloser struct {
	closed bool
}

func (m *mockCloser) Close() error {
	m.closed = true
	return nil
}

// mockSSHChannel implements ssh.Channel for testing
type mockSSHChannel struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func (m *mockSSHChannel) Read(data []byte) (int, error) {
	if m.closed {
		return 0, io.EOF
	}
	return m.readBuf.Read(data)
}

func (m *mockSSHChannel) Write(data []byte) (int, error) {
	if m.closed {
		return 0, errors.New("channel closed")
	}
	return m.writeBuf.Write(data)
}

func (m *mockSSHChannel) Close() error {
	m.closed = true
	return nil
}

func (m *mockSSHChannel) CloseWrite() error {
	return nil
}

func (m *mockSSHChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return true, nil
}

func (m *mockSSHChannel) Stderr() io.ReadWriter {
	return m
}
