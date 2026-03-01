package uproxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type mockReadWriteCloser struct {
	reader io.Reader
	writer io.Writer
	closed bool
}

func (m *mockReadWriteCloser) Read(p []byte) (n int, err error) {
	return m.reader.Read(p)
}

func (m *mockReadWriteCloser) Write(p []byte) (n int, err error) {
	return m.writer.Write(p)
}

func (m *mockReadWriteCloser) Close() error {
	m.closed = true
	return nil
}

func TestProxyBidi(t *testing.T) {
	// Create two pipe pairs for bidirectional communication
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()

	client := &mockReadWriteCloser{
		reader: clientRead,
		writer: clientWrite,
	}
	server := &mockReadWriteCloser{
		reader: serverRead,
		writer: serverWrite,
	}

	ctx := context.Background()

	// Start proxy in goroutine
	done := make(chan error, 1)
	go func() {
		done <- ProxyBidi(ctx, client, server, "test", "localhost:8080", 4096)
	}()

	// Send some data from client to server
	testData := []byte("hello from client")
	go func() {
		clientWrite.Write(testData)
		clientWrite.Close()
	}()

	// Read on server side
	buf := make([]byte, len(testData))
	n, err := io.ReadFull(serverRead, buf)
	if err != nil {
		t.Errorf("Failed to read from server: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected %d bytes, got %d", len(testData), n)
	}
	if string(buf) != string(testData) {
		t.Errorf("Expected %q, got %q", testData, buf)
	}

	// Close server side to trigger proxy completion
	serverRead.Close()
	serverWrite.Close()

	// Wait for proxy to complete
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("ProxyBidi did not complete in time")
	}
}

func TestProxyBidiWithContext(t *testing.T) {
	// Create pipes
	clientRead, serverWrite := io.Pipe()
	serverRead, clientWrite := io.Pipe()

	client := &mockReadWriteCloser{
		reader: clientRead,
		writer: clientWrite,
	}
	server := &mockReadWriteCloser{
		reader: serverRead,
		writer: serverWrite,
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Start proxy
	done := make(chan error, 1)
	go func() {
		done <- ProxyBidi(ctx, client, server, "test", "localhost:8080", 8192)
	}()

	// Cancel context immediately
	cancel()

	// Close pipes to allow proxy to exit
	clientRead.Close()
	clientWrite.Close()
	serverRead.Close()
	serverWrite.Close()

	// Wait for completion
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("ProxyBidi did not complete after context cancellation")
	}
}

func TestOptimizeTCPConn(t *testing.T) {
	// Create a TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	// Accept connection in goroutine
	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		acceptDone <- conn
	}()

	// Connect to listener
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Wait for accept
	serverConn := <-acceptDone
	if serverConn != nil {
		defer serverConn.Close()
	}

	// Test OptimizeTCPConn with TCP connection
	OptimizeTCPConn(conn)

	// Verify connection still works
	testData := []byte("test")
	_, err = conn.Write(testData)
	if err != nil {
		t.Errorf("Failed to write after optimization: %v", err)
	}

	// Test with non-TCP connection (should not panic)
	type fakeConn struct {
		net.Conn
	}
	OptimizeTCPConn(&fakeConn{})
}

func TestOptimizeTCPConnError(t *testing.T) {
	// Create a TCP connection and close it to trigger SetNoDelay error
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		acceptDone <- conn
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	serverConn := <-acceptDone
	if serverConn != nil {
		serverConn.Close()
	}

	// Close the connection before calling OptimizeTCPConn
	conn.Close()

	// This should trigger the error path in OptimizeTCPConn
	OptimizeTCPConn(conn)
}

func TestProxyBidiBufferSizes(t *testing.T) {
	bufferSizes := []int{1024, 4096, 8192, 16384, 32768}

	for _, bufSize := range bufferSizes {
		t.Run("bufsize_"+string(rune(bufSize)), func(t *testing.T) {
			clientRead, serverWrite := io.Pipe()
			serverRead, clientWrite := io.Pipe()

			client := &mockReadWriteCloser{
				reader: clientRead,
				writer: clientWrite,
			}
			server := &mockReadWriteCloser{
				reader: serverRead,
				writer: serverWrite,
			}

			ctx := context.Background()

			done := make(chan error, 1)
			go func() {
				done <- ProxyBidi(ctx, client, server, "test", "target", bufSize)
			}()

			// Close immediately
			clientRead.Close()
			clientWrite.Close()
			serverRead.Close()
			serverWrite.Close()

			select {
			case <-done:
				// Success
			case <-time.After(1 * time.Second):
				t.Error("ProxyBidi did not complete")
			}
		})
	}
}
