package uproxy

import (
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type mockChannel struct {
	ssh.Channel
	readData  []byte
	writeData []byte
	closed    bool
}

func (m *mockChannel) Read(data []byte) (int, error) {
	if len(m.readData) == 0 {
		return 0, nil
	}
	n := copy(data, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockChannel) Write(data []byte) (int, error) {
	m.writeData = append(m.writeData, data...)
	return len(data), nil
}

func (m *mockChannel) Close() error {
	m.closed = true
	return nil
}

func (m *mockChannel) CloseWrite() error {
	return nil
}

func (m *mockChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return true, nil
}

func (m *mockChannel) Stderr() io.ReadWriter {
	return nil
}

func TestNewChannelConn(t *testing.T) {
	mockCh := &mockChannel{
		readData: []byte("test data"),
	}

	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	if conn == nil {
		t.Fatal("Expected non-nil ChannelConn")
	}

	// Verify channel is set (can't directly compare interface)
	if conn.Channel == nil {
		t.Error("Channel not set correctly")
	}

	if conn.localAddr != localAddr {
		t.Error("Local address not set correctly")
	}

	if conn.remoteAddr != remoteAddr {
		t.Error("Remote address not set correctly")
	}
}

func TestChannelConnLocalAddr(t *testing.T) {
	mockCh := &mockChannel{}
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	if conn.LocalAddr() != localAddr {
		t.Errorf("Expected local address %v, got %v", localAddr, conn.LocalAddr())
	}
}

func TestChannelConnRemoteAddr(t *testing.T) {
	mockCh := &mockChannel{}
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	if conn.RemoteAddr() != remoteAddr {
		t.Errorf("Expected remote address %v, got %v", remoteAddr, conn.RemoteAddr())
	}
}

func TestChannelConnSetDeadline(t *testing.T) {
	mockCh := &mockChannel{}
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	deadline := time.Now().Add(1 * time.Second)
	err := conn.SetDeadline(deadline)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestChannelConnSetReadDeadline(t *testing.T) {
	mockCh := &mockChannel{}
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	deadline := time.Now().Add(1 * time.Second)
	err := conn.SetReadDeadline(deadline)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestChannelConnSetWriteDeadline(t *testing.T) {
	mockCh := &mockChannel{}
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	deadline := time.Now().Add(1 * time.Second)
	err := conn.SetWriteDeadline(deadline)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestChannelConnReadWrite(t *testing.T) {
	testData := []byte("hello world")
	mockCh := &mockChannel{
		readData: testData,
	}

	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	// Test Read
	buf := make([]byte, len(testData))
	n, err := conn.Read(buf)
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to read %d bytes, got %d", len(testData), n)
	}
	if string(buf) != string(testData) {
		t.Errorf("Expected %q, got %q", testData, buf)
	}

	// Test Write
	writeData := []byte("test write")
	n, err = conn.Write(writeData)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	if n != len(writeData) {
		t.Errorf("Expected to write %d bytes, got %d", len(writeData), n)
	}
	if string(mockCh.writeData) != string(writeData) {
		t.Errorf("Expected %q, got %q", writeData, mockCh.writeData)
	}
}

func TestChannelConnClose(t *testing.T) {
	mockCh := &mockChannel{}
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	err := conn.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	if !mockCh.closed {
		t.Error("Expected channel to be closed")
	}
}
