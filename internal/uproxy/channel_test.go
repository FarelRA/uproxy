package uproxy

import (
	"net"
	"testing"
	"time"

	"uproxy/internal/testutil"
)

func TestNewChannelConn(t *testing.T) {
	mockCh := testutil.NewMockSSHChannel()
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	if conn == nil {
		t.Fatal("Expected non-nil ChannelConn")
	}

	if conn.LocalAddr() != localAddr {
		t.Errorf("Expected local address %v, got %v", localAddr, conn.LocalAddr())
	}

	if conn.RemoteAddr() != remoteAddr {
		t.Errorf("Expected remote address %v, got %v", remoteAddr, conn.RemoteAddr())
	}
}

func TestChannelConnRead(t *testing.T) {
	mockCh := testutil.NewMockSSHChannel()
	mockCh.ReadBuf.Write([]byte("test data"))
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if n != 9 {
		t.Errorf("Expected to read 9 bytes, got %d", n)
	}

	if string(buf[:n]) != "test data" {
		t.Errorf("Expected 'test data', got '%s'", string(buf[:n]))
	}
}

func TestChannelConnRemoteAddr(t *testing.T) {
	mockCh := testutil.NewMockSSHChannel()
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	if conn.RemoteAddr() != remoteAddr {
		t.Errorf("Expected remote address %v, got %v", remoteAddr, conn.RemoteAddr())
	}
}

func TestChannelConnSetDeadline(t *testing.T) {
	mockCh := testutil.NewMockSSHChannel()
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
	mockCh := testutil.NewMockSSHChannel()
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
	mockCh := testutil.NewMockSSHChannel()
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
	mockCh := testutil.NewMockSSHChannel()
	mockCh.ReadBuf.Write(testData)

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
	if string(mockCh.WriteBuf.Bytes()) != string(writeData) {
		t.Errorf("Expected %q, got %q", writeData, mockCh.WriteBuf.Bytes())
	}
}

func TestChannelConnClose(t *testing.T) {
	mockCh := testutil.NewMockSSHChannel()
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5678}

	conn := NewChannelConn(mockCh, localAddr, remoteAddr)

	err := conn.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	if !mockCh.Closed {
		t.Error("Expected channel to be closed")
	}
}
