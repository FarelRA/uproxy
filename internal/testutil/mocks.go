package testutil

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// MockConn implements net.Conn for testing
type MockConn struct {
	ReadBuf  *bytes.Buffer
	WriteBuf *bytes.Buffer
	Closed   bool
	mu       sync.Mutex
}

// NewMockConn creates a new MockConn with initialized buffers
func NewMockConn() *MockConn {
	return &MockConn{
		ReadBuf:  new(bytes.Buffer),
		WriteBuf: new(bytes.Buffer),
	}
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Closed {
		return 0, io.EOF
	}
	return m.ReadBuf.Read(b)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Closed {
		return 0, errors.New("connection closed")
	}
	return m.WriteBuf.Write(b)
}

func (m *MockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Closed = true
	return nil
}

func (m *MockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *MockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// MockSSHChannel implements ssh.Channel for testing
type MockSSHChannel struct {
	ReadBuf  *bytes.Buffer
	WriteBuf *bytes.Buffer
	Closed   bool
	mu       sync.Mutex
}

// NewMockSSHChannel creates a new MockSSHChannel with initialized buffers
func NewMockSSHChannel() *MockSSHChannel {
	return &MockSSHChannel{
		ReadBuf:  new(bytes.Buffer),
		WriteBuf: new(bytes.Buffer),
	}
}

func (m *MockSSHChannel) Read(data []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Closed {
		return 0, io.EOF
	}
	return m.ReadBuf.Read(data)
}

func (m *MockSSHChannel) Write(data []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Closed {
		return 0, errors.New("channel closed")
	}
	return m.WriteBuf.Write(data)
}

func (m *MockSSHChannel) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Closed = true
	return nil
}

func (m *MockSSHChannel) CloseWrite() error {
	return nil
}

func (m *MockSSHChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return true, nil
}

func (m *MockSSHChannel) Stderr() io.ReadWriter {
	return m
}

// MockCloser implements io.Closer for testing
type MockCloser struct {
	Closed bool
	mu     sync.Mutex
}

// NewMockCloser creates a new MockCloser
func NewMockCloser() *MockCloser {
	return &MockCloser{}
}

func (m *MockCloser) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Closed = true
	return nil
}
