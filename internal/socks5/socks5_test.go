package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"uproxy/internal/config"
	"uproxy/internal/testutil"
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
			conn := testutil.NewMockConn()
			conn.ReadBuf = bytes.NewBuffer(tt.clientData)

			err := performSOCKS5Handshake(conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("performSOCKS5Handshake() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				// Check response
				resp := conn.WriteBuf.Bytes()
				if len(resp) != 2 || resp[0] != 0x05 || resp[1] != 0x00 {
					t.Errorf("Invalid handshake response: %v", resp)
				}
			}
		})
	}
}

func TestPerformSOCKS5HandshakeNoAcceptableMethod(t *testing.T) {
	conn := testutil.NewMockConn()
	conn.ReadBuf = bytes.NewBuffer([]byte{
		0x05, // version
		0x01, // method count
		0x02, // username/password only
	})

	err := performSOCKS5Handshake(conn)
	if err == nil {
		t.Fatal("performSOCKS5Handshake() expected error for unsupported auth methods")
	}

	resp := conn.WriteBuf.Bytes()
	if len(resp) != 2 || resp[0] != 0x05 || resp[1] != 0xff {
		t.Fatalf("unexpected handshake response: %v", resp)
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
			name: "invalid reserved byte",
			data: []byte{
				0x05,
				config.SOCKS5CommandConnect,
				0x01,
				config.SOCKS5AddressIPv4,
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
			conn := testutil.NewMockConn()
			conn.ReadBuf = bytes.NewBuffer(tt.data)

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
		conn := testutil.NewMockConn()
		remoteConn := testutil.NewMockConn()
		remoteConn.ReadBuf.Write([]byte("response"))

		dialTCP := func(ctx context.Context, addr string) (net.Conn, error) {
			return remoteConn, nil
		}

		handleConnectCommand(context.Background(), conn, "example.com:80", "127.0.0.1:12345", config.DefaultTCPBufSize, dialTCP)

		// Check success response
		resp := conn.WriteBuf.Bytes()
		if len(resp) < 10 || resp[0] != 0x05 || resp[1] != 0x00 {
			t.Errorf("Invalid success response: %v", resp)
		}
	})

	t.Run("failed connect", func(t *testing.T) {
		conn := testutil.NewMockConn()

		dialTCP := func(ctx context.Context, addr string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}

		handleConnectCommand(context.Background(), conn, "example.com:80", "127.0.0.1:12345", config.DefaultTCPBufSize, dialTCP)

		// Check error response
		resp := conn.WriteBuf.Bytes()
		if len(resp) < 10 || resp[0] != 0x05 || resp[1] != config.SOCKS5ReplyGeneralFailure {
			t.Errorf("Invalid error response: %v", resp)
		}
	})
}

// TestHandleUDPAssociate tests UDP ASSOCIATE handling
func TestHandleUDPAssociate(t *testing.T) {
	t.Run("successful UDP associate IPv4", func(t *testing.T) {
		conn := testutil.NewMockConn()

		udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}
		closer := testutil.NewMockCloser()

		dialUDP := func(ctx context.Context) (net.Addr, io.Closer, error) {
			return udpAddr, closer, nil
		}

		handleUDPAssociate(context.Background(), conn, "127.0.0.1:12345", dialUDP)

		// Check response
		resp := conn.WriteBuf.Bytes()
		if len(resp) < 10 || resp[0] != 0x05 || resp[1] != 0x00 {
			t.Errorf("Invalid UDP associate response: %v", resp)
		}

	})

	t.Run("successful UDP associate IPv6", func(t *testing.T) {
		conn := testutil.NewMockConn()

		udpAddr := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 5000}
		closer := testutil.NewMockCloser()

		dialUDP := func(ctx context.Context) (net.Addr, io.Closer, error) {
			return udpAddr, closer, nil
		}

		handleUDPAssociate(context.Background(), conn, "127.0.0.1:12345", dialUDP)

		// Check response
		resp := conn.WriteBuf.Bytes()
		if len(resp) < 22 || resp[0] != 0x05 || resp[1] != 0x00 || resp[3] != 0x04 {
			t.Errorf("Invalid UDP associate IPv6 response: %v", resp)
		}

	})

	t.Run("failed UDP associate", func(t *testing.T) {
		conn := testutil.NewMockConn()

		dialUDP := func(ctx context.Context) (net.Addr, io.Closer, error) {
			return nil, nil, errors.New("bind failed")
		}

		handleUDPAssociate(context.Background(), conn, "127.0.0.1:12345", dialUDP)

		// Check error response
		resp := conn.WriteBuf.Bytes()
		if len(resp) < 10 || resp[0] != 0x05 || resp[1] != config.SOCKS5ReplyGeneralFailure {
			t.Errorf("Invalid error response: %v", resp)
		}
	})
}

// TestBufferPool tests UDP buffer pool
func TestBufferPool(t *testing.T) {
	buf1 := udpBufferPool.Get()
	if buf1 == nil || len(*buf1) != udpBufSize {
		t.Errorf("udpBufferPool.Get() returned invalid buffer")
	}

	udpBufferPool.Put(buf1)

	buf2 := udpBufferPool.Get()
	if buf2 == nil || len(*buf2) != udpBufSize {
		t.Errorf("udpBufferPool.Get() after put returned invalid buffer")
	}

	// Test putting nil buffer
	udpBufferPool.Put(nil)

	// Test putting wrong size buffer
	wrongSize := make([]byte, 100)
	udpBufferPool.Put(&wrongSize)
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

		conn := testutil.NewMockConn()
		conn.ReadBuf = bytes.NewBuffer(data)

		dialTCP := func(ctx context.Context, addr string) (net.Conn, error) {
			return nil, errors.New("should not be called")
		}

		dialUDP := func(ctx context.Context) (net.Addr, io.Closer, error) {
			return nil, nil, errors.New("should not be called")
		}

		var clientWg sync.WaitGroup
		clientWg.Add(1)
		handleSOCKS5Client(context.Background(), conn, config.DefaultTCPBufSize, dialTCP, dialUDP, &clientWg)

		// Check that unsupported command response was sent
		resp := conn.WriteBuf.Bytes()
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

// TestServeSOCKS5_ContextCancellation tests that ServeSOCKS5 shuts down cleanly on context cancellation
func TestServeSOCKS5_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	dialTCP := func(ctx context.Context, addr string) (net.Conn, error) {
		return nil, errors.New("should not be called")
	}

	dialUDP := func(ctx context.Context) (net.Addr, io.Closer, error) {
		return nil, nil, errors.New("should not be called")
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- ServeSOCKS5(ctx, "127.0.0.1:0", config.DefaultTCPBufSize, dialTCP, dialUDP)
	}()

	// Give the server time to start
	time.Sleep(50 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for shutdown
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			t.Errorf("Expected nil or context.Canceled error on clean shutdown, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Error("ServeSOCKS5 did not shut down after context cancellation")
	}
}

// TestSOCKS5_ConcurrentRequests tests handling multiple concurrent SOCKS5 connections
func TestSOCKS5_ConcurrentRequests(t *testing.T) {
	const numRequests = 10

	dialTCP := func(ctx context.Context, addr string) (net.Conn, error) {
		// Return a mock connection
		return testutil.NewMockConn(), nil
	}

	dialUDP := func(ctx context.Context) (net.Addr, io.Closer, error) {
		return nil, nil, errors.New("UDP not supported in this test")
	}

	// Test concurrent CONNECT requests
	var wg sync.WaitGroup
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Handshake + CONNECT request
			data := []byte{
				// Handshake
				0x05, 0x01, 0x00,
				// Request
				0x05, 0x01, 0x00, 0x01, // CONNECT
				192, 168, 1, 1,
				0x00, 0x50,
			}

			conn := testutil.NewMockConn()
			conn.ReadBuf = bytes.NewBuffer(data)

			var clientWg sync.WaitGroup
			clientWg.Add(1)
			handleSOCKS5Client(context.Background(), conn, config.DefaultTCPBufSize, dialTCP, dialUDP, &clientWg)
		}()
	}

	// Wait for all requests to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Error("Concurrent requests did not complete in time")
	}
}

// TestSOCKS5_LargeDataTransfer tests handling of large data transfers
func TestSOCKS5_LargeDataTransfer(t *testing.T) {
	// Create a large payload (10KB)
	largePayload := make([]byte, 10*1024)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	// Test with UDP header parsing
	header := []byte{
		0x00, 0x00, // RSV
		0x00,           // FRAG
		0x01,           // ATYP (IPv4)
		192, 168, 1, 1, // Address
		0x00, 0x50, // Port
	}

	fullData := append(header, largePayload...)

	target, payload, parsedHeader, err := parseSOCKS5UDPHeader(fullData)
	if err != nil {
		t.Fatalf("parseSOCKS5UDPHeader() failed with large payload: %v", err)
	}

	if target != "192.168.1.1:80" {
		t.Errorf("parseSOCKS5UDPHeader() target = %v, want 192.168.1.1:80", target)
	}

	if !bytes.Equal(payload, largePayload) {
		t.Error("parseSOCKS5UDPHeader() payload corrupted for large data")
	}

	if parsedHeader == nil {
		t.Error("parseSOCKS5UDPHeader() header is nil")
	}
}

// TestSOCKS5_IPv6Handling tests IPv6 address handling in SOCKS5
func TestSOCKS5_IPv6Handling(t *testing.T) {
	tests := []struct {
		name       string
		request    []byte
		wantTarget string
		wantCmd    byte
		wantErr    bool
	}{
		{
			name: "valid IPv6 CONNECT",
			request: []byte{
				0x05, 0x01, 0x00, 0x04, // CONNECT, IPv6
				0x20, 0x01, 0x0d, 0xb8, // 2001:db8::1
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x50, // Port 80
			},
			wantTarget: "[2001:db8::1]:80",
			wantCmd:    config.SOCKS5CommandConnect,
			wantErr:    false,
		},
		{
			name: "truncated IPv6 address",
			request: []byte{
				0x05, 0x01, 0x00, 0x04, // CONNECT, IPv6
				0x20, 0x01, 0x0d, 0xb8, // Incomplete address
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := testutil.NewMockConn()
			conn.ReadBuf = bytes.NewBuffer(tt.request)

			cmd, target, err := parseSOCKS5Request(conn)

			if tt.wantErr {
				if err == nil {
					t.Error("parseSOCKS5Request() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseSOCKS5Request() unexpected error: %v", err)
				return
			}

			if cmd != tt.wantCmd {
				t.Errorf("parseSOCKS5Request() cmd = %v, want %v", cmd, tt.wantCmd)
			}

			if target != tt.wantTarget {
				t.Errorf("parseSOCKS5Request() target = %v, want %v", target, tt.wantTarget)
			}
		})
	}

	// Test IPv6 in UDP header
	t.Run("IPv6 UDP header", func(t *testing.T) {
		header := []byte{
			0x00, 0x00, // RSV
			0x00,                   // FRAG
			0x04,                   // ATYP (IPv6)
			0x20, 0x01, 0x0d, 0xb8, // 2001:db8::1
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01,
			0x00, 0x50, // Port 80
			0x01, 0x02, 0x03, // Payload
		}

		target, payload, parsedHeader, err := parseSOCKS5UDPHeader(header)
		if err != nil {
			t.Fatalf("parseSOCKS5UDPHeader() failed for IPv6: %v", err)
		}

		if target != "[2001:db8::1]:80" {
			t.Errorf("parseSOCKS5UDPHeader() target = %v, want [2001:db8::1]:80", target)
		}

		if !bytes.Equal(payload, []byte{0x01, 0x02, 0x03}) {
			t.Errorf("parseSOCKS5UDPHeader() payload = %v, want [1 2 3]", payload)
		}

		if parsedHeader == nil {
			t.Error("parseSOCKS5UDPHeader() header is nil")
		}
	})
}
