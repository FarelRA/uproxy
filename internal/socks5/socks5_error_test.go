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

// TestHandshakeErrors tests various error conditions during SOCKS5 handshake
func TestHandshakeErrors(t *testing.T) {
	tests := []struct {
		name      string
		setupConn func() *testutil.MockConn
		wantErr   bool
	}{
		{
			name: "read error during methods read",
			setupConn: func() *testutil.MockConn {
				conn := testutil.NewMockConn()
				conn.ReadBuf = bytes.NewBuffer([]byte{0x05, 0x02})
				// Will fail when trying to read 2 method bytes
				return conn
			},
			wantErr: true,
		},
		{
			name: "zero methods",
			setupConn: func() *testutil.MockConn {
				conn := testutil.NewMockConn()
				conn.ReadBuf = bytes.NewBuffer([]byte{0x05, 0x00}) // version 5, 0 methods
				return conn
			},
			wantErr: true,
		},
		{
			name: "unsupported SOCKS version",
			setupConn: func() *testutil.MockConn {
				conn := testutil.NewMockConn()
				conn.ReadBuf = bytes.NewBuffer([]byte{0x04, 0x01, 0x00})
				return conn
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := tt.setupConn()
			err := performSOCKS5Handshake(conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("performSOCKS5Handshake() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRequestParsingErrors tests error conditions during request parsing
func TestRequestParsingErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty request",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "truncated header",
			data:    []byte{0x05, 0x01},
			wantErr: true,
		},
		{
			name: "invalid reserved byte",
			data: []byte{
				0x05, 0x01, 0xFF, 0x01, // RSV should be 0x00
				192, 168, 1, 1,
				0x00, 0x50,
			},
			wantErr: true,
		},
		{
			name: "domain name too long",
			data: func() []byte {
				data := []byte{0x05, 0x01, 0x00, 0x03, 0xFF} // 255 byte domain
				data = append(data, make([]byte, 255)...)
				data = append(data, 0x00, 0x50)
				return data
			}(),
			wantErr: false, // Should handle max length domain
		},
		{
			name: "truncated port",
			data: []byte{
				0x05, 0x01, 0x00, 0x01,
				192, 168, 1, 1,
				0x00, // Missing second port byte
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := testutil.NewMockConn()
			conn.ReadBuf = bytes.NewBuffer(tt.data)

			_, _, err := parseSOCKS5Request(conn)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSOCKS5Request() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConnectCommandErrors tests error handling in TCP CONNECT
func TestConnectCommandErrors(t *testing.T) {
	tests := []struct {
		name         string
		dialErr      error
		wantRespCode byte
	}{
		{
			name:         "connection refused",
			dialErr:      errors.New("connection refused"),
			wantRespCode: config.SOCKS5ReplyGeneralFailure,
		},
		{
			name:         "network unreachable",
			dialErr:      errors.New("network unreachable"),
			wantRespCode: config.SOCKS5ReplyGeneralFailure,
		},
		{
			name:         "timeout",
			dialErr:      context.DeadlineExceeded,
			wantRespCode: config.SOCKS5ReplyGeneralFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := testutil.NewMockConn()

			dialTCP := func(ctx context.Context, addr string) (net.Conn, error) {
				return nil, tt.dialErr
			}

			handleConnectCommand(context.Background(), conn, "example.com:80", "127.0.0.1:12345", config.DefaultTCPBufSize, dialTCP)

			resp := conn.WriteBuf.Bytes()
			if len(resp) < 2 {
				t.Fatalf("Response too short: %v", resp)
			}
			if resp[0] != 0x05 {
				t.Errorf("Invalid SOCKS version in response: %v", resp[0])
			}
			if resp[1] != tt.wantRespCode {
				t.Errorf("Expected response code %v, got %v", tt.wantRespCode, resp[1])
			}
		})
	}
}

// TestUDPAssociateErrors tests error handling in UDP ASSOCIATE
func TestUDPAssociateErrors(t *testing.T) {
	tests := []struct {
		name         string
		dialErr      error
		wantRespCode byte
	}{
		{
			name:         "bind failed",
			dialErr:      errors.New("bind: address already in use"),
			wantRespCode: config.SOCKS5ReplyGeneralFailure,
		},
		{
			name:         "permission denied",
			dialErr:      errors.New("bind: permission denied"),
			wantRespCode: config.SOCKS5ReplyGeneralFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := testutil.NewMockConn()

			dialUDP := func(ctx context.Context) (net.Addr, io.Closer, error) {
				return nil, nil, tt.dialErr
			}

			handleUDPAssociate(context.Background(), conn, "127.0.0.1:12345", dialUDP)

			resp := conn.WriteBuf.Bytes()
			if len(resp) < 2 {
				t.Fatalf("Response too short: %v", resp)
			}
			if resp[0] != 0x05 {
				t.Errorf("Invalid SOCKS version in response: %v", resp[0])
			}
			if resp[1] != tt.wantRespCode {
				t.Errorf("Expected response code %v, got %v", tt.wantRespCode, resp[1])
			}
		})
	}
}

// TestContextCancellation tests proper handling of context cancellation
func TestContextCancellation(t *testing.T) {
	t.Run("cancel during CONNECT", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		conn := testutil.NewMockConn()
		remoteConn := testutil.NewMockConn()

		dialTCP := func(ctx context.Context, addr string) (net.Conn, error) {
			// Simulate slow connection
			time.Sleep(100 * time.Millisecond)
			return remoteConn, nil
		}

		// Cancel immediately
		cancel()

		handleConnectCommand(ctx, conn, "example.com:80", "127.0.0.1:12345", config.DefaultTCPBufSize, dialTCP)

		// Should send error response
		resp := conn.WriteBuf.Bytes()
		if len(resp) < 2 {
			t.Fatalf("Response too short: %v", resp)
		}
	})

	t.Run("cancel during UDP associate", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		serverConn, clientConn := net.Pipe()
		defer clientConn.Close()

		udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}
		closer := testutil.NewMockCloser()

		dialUDP := func(ctx context.Context) (net.Addr, io.Closer, error) {
			return udpAddr, closer, nil
		}

		done := make(chan struct{})
		go func() {
			handleUDPAssociate(ctx, serverConn, "127.0.0.1:12345", dialUDP)
			close(done)
		}()

		resp := make([]byte, 10)
		if _, err := io.ReadFull(clientConn, resp); err != nil {
			t.Fatalf("failed to read UDP associate response: %v", err)
		}

		// Cancel context
		cancel()

		clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		var buf [1]byte
		_, err := clientConn.Read(buf[:])
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected connection close after cancellation, got %v", err)
		}

		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
			t.Fatal("handleUDPAssociate did not return after context cancellation")
		}
	})
}

// TestUDPHeaderErrors tests error handling in UDP header parsing
func TestUDPHeaderErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "header too short",
			data:    []byte{0x00, 0x00},
			wantErr: true,
		},
		{
			name: "fragmentation not zero",
			data: []byte{
				0x00, 0x00, 0x01, // FRAG != 0
				0x01, 192, 168, 1, 1,
				0x00, 0x50,
			},
			wantErr: true,
		},
		{
			name: "invalid address type",
			data: []byte{
				0x00, 0x00, 0x00,
				0xFF, // Invalid ATYP
				192, 168, 1, 1,
				0x00, 0x50,
			},
			wantErr: true,
		},
		{
			name: "domain length zero",
			data: []byte{
				0x00, 0x00, 0x00,
				0x03, // Domain
				0x00, // Length 0
				0x00, 0x50,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := parseSOCKS5UDPHeader(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSOCKS5UDPHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestWriteSOCKS5Responses tests response writing functions
func TestWriteSOCKS5Responses(t *testing.T) {
	t.Run("write success response", func(t *testing.T) {
		conn := testutil.NewMockConn()
		err := writeSOCKS5Success(conn, "192.168.1.1:8080")
		if err != nil {
			t.Errorf("writeSOCKS5Success() error = %v", err)
		}

		resp := conn.WriteBuf.Bytes()
		if len(resp) < 10 {
			t.Errorf("Response too short: %v", resp)
		}
		if resp[0] != 0x05 {
			t.Errorf("Invalid SOCKS version: %v", resp[0])
		}
		if resp[1] != 0x00 {
			t.Errorf("Expected success code 0x00, got %v", resp[1])
		}
	})

	t.Run("write error response", func(t *testing.T) {
		conn := testutil.NewMockConn()
		err := writeSOCKS5Error(conn, 0x05)
		if err != nil {
			t.Errorf("writeSOCKS5Error() error = %v", err)
		}

		resp := conn.WriteBuf.Bytes()
		if len(resp) < 10 {
			t.Errorf("Response too short: %v", resp)
		}
		if resp[0] != 0x05 {
			t.Errorf("Invalid SOCKS version: %v", resp[0])
		}
		if resp[1] != 0x05 {
			t.Errorf("Expected error code 0x05, got %v", resp[1])
		}
	})
}

// TestReadSOCKS5HostErrors tests error handling in host reading
func TestReadSOCKS5HostErrors(t *testing.T) {
	tests := []struct {
		name    string
		atyp    byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "IPv4 truncated",
			atyp:    config.SOCKS5AddressIPv4,
			data:    []byte{192, 168},
			wantErr: true,
		},
		{
			name:    "IPv6 truncated",
			atyp:    config.SOCKS5AddressIPv6,
			data:    []byte{0, 0, 0, 0},
			wantErr: true,
		},
		{
			name:    "domain length read error",
			atyp:    config.SOCKS5AddressDomain,
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "domain data truncated",
			atyp:    config.SOCKS5AddressDomain,
			data:    []byte{0x0a, 'a', 'b'},
			wantErr: true,
		},
		{
			name:    "unsupported address type",
			atyp:    0x99,
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := testutil.NewMockConn()
			conn.ReadBuf = bytes.NewBuffer(tt.data)

			_, err := readSOCKS5Host(conn, tt.atyp)
			if (err != nil) != tt.wantErr {
				t.Errorf("readSOCKS5Host() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestConcurrentHandshakes tests concurrent handshake handling
func TestConcurrentHandshakes(t *testing.T) {
	const numConcurrent = 50

	var wg sync.WaitGroup
	errors := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			conn := testutil.NewMockConn()
			conn.ReadBuf = bytes.NewBuffer([]byte{0x05, 0x01, 0x00})

			err := performSOCKS5Handshake(conn)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent handshake failed: %v", err)
	}
}

// TestTargetHeaderEdgeCases tests edge cases in target header encoding/decoding
func TestTargetHeaderEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{
			name:    "empty target",
			target:  "",
			wantErr: false,
		},
		{
			name:    "very long target",
			target:  string(make([]byte, 65535)) + ":80",
			wantErr: true,
		},
		{
			name:    "special characters",
			target:  "test-domain_123.example.com:8080",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}

			err := WriteTargetHeader(buf, tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTargetHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				target, err := ReadTargetHeader(buf)
				if err != nil {
					t.Errorf("ReadTargetHeader() error = %v", err)
					return
				}
				if target != tt.target {
					t.Errorf("ReadTargetHeader() = %v, want %v", target, tt.target)
				}
			}
		})
	}
}
