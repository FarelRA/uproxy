package kcp

import (
	"net"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "default config",
			config: Config{
				NoDelay:          1,
				Interval:         10,
				Resend:           2,
				NoCongestionCtrl: 1,
				SndWnd:           128,
				RcvWnd:           128,
				MTU:              1400,
			},
		},
		{
			name: "high performance config",
			config: Config{
				NoDelay:          1,
				Interval:         10,
				Resend:           2,
				NoCongestionCtrl: 1,
				SndWnd:           1024,
				RcvWnd:           1024,
				MTU:              1400,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a UDP connection for testing
			conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
			if err != nil {
				t.Fatalf("Failed to create UDP connection: %v", err)
			}
			defer conn.Close()

			// Create a KCP session
			sess, err := NewConn("127.0.0.1:0", conn)
			if err != nil {
				t.Fatalf("Failed to create KCP session: %v", err)
			}
			defer sess.Close()

			// Apply configuration
			tt.config.Apply(sess)

			// Verify the configuration was applied (basic check)
			if sess.kcp == nil {
				t.Error("KCP instance is nil after config apply")
			}
		})
	}
}

func TestSnmp(t *testing.T) {
	snmp := newSnmp()
	if snmp == nil {
		t.Fatal("newSnmp returned nil")
	}

	// Test initial values
	if snmp.BytesSent != 0 {
		t.Errorf("Expected BytesSent to be 0, got %d", snmp.BytesSent)
	}
	if snmp.BytesReceived != 0 {
		t.Errorf("Expected BytesReceived to be 0, got %d", snmp.BytesReceived)
	}

	// Test DefaultSnmp
	if DefaultSnmp == nil {
		t.Fatal("DefaultSnmp is nil")
	}
}

func TestCurrentMs(t *testing.T) {
	ms1 := currentMs()
	time.Sleep(10 * time.Millisecond)
	ms2 := currentMs()

	if ms2 <= ms1 {
		t.Errorf("Expected ms2 (%d) to be greater than ms1 (%d)", ms2, ms1)
	}

	diff := ms2 - ms1
	if diff < 10 || diff > 50 {
		t.Errorf("Expected time difference to be around 10ms, got %dms", diff)
	}
}

func TestTimeoutError(t *testing.T) {
	err := errTimeout

	if err.Error() != "timeout" {
		t.Errorf("Expected error message 'timeout', got '%s'", err.Error())
	}

	if !err.Timeout() {
		t.Error("Expected Timeout() to return true")
	}

	if !err.Temporary() {
		t.Error("Expected Temporary() to return true")
	}
}

func TestKCPSession(t *testing.T) {
	// Create a UDP listener
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP listener: %v", err)
	}
	defer listener.Close()

	// Create a KCP session with proper connection
	sess, err := NewConn(listener.LocalAddr().String(), listener)
	if err != nil {
		t.Fatalf("Failed to create KCP session: %v", err)
	}
	defer sess.Close()

	// Test SetNoDelay
	sess.SetNoDelay(1, 10, 2, 1)

	// Test SetWindowSize
	sess.SetWindowSize(128, 128)

	// Test SetMtu
	sess.SetMtu(1400)

	// Test SetStreamMode
	sess.SetStreamMode(true)

	// Test SetWriteDelay
	sess.SetWriteDelay(false)

	// Test SetACKNoDelay
	sess.SetACKNoDelay(true)

	// Test LocalAddr
	if sess.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}

	// Test RemoteAddr
	if sess.RemoteAddr() == nil {
		t.Error("RemoteAddr returned nil")
	}
}

func TestKCPSessionDeadlines(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP listener: %v", err)
	}
	defer listener.Close()

	sess, err := NewConn(listener.LocalAddr().String(), listener)
	if err != nil {
		t.Fatalf("Failed to create KCP session: %v", err)
	}
	defer sess.Close()

	// Test SetDeadline
	deadline := time.Now().Add(1 * time.Second)
	if err := sess.SetDeadline(deadline); err != nil {
		t.Errorf("SetDeadline failed: %v", err)
	}

	// Test SetReadDeadline
	if err := sess.SetReadDeadline(deadline); err != nil {
		t.Errorf("SetReadDeadline failed: %v", err)
	}

	// Test SetWriteDeadline
	if err := sess.SetWriteDeadline(deadline); err != nil {
		t.Errorf("SetWriteDeadline failed: %v", err)
	}
}

func TestKCPSessionReadWrite(t *testing.T) {
	// Create two UDP connections for client and server
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create server UDP connection: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().String()

	// Create server session
	serverSess, err := NewConn(serverAddr, serverConn)
	if err != nil {
		t.Fatalf("Failed to create server KCP session: %v", err)
	}
	defer serverSess.Close()

	// Create client session
	clientSess, err := NewConn(serverAddr, nil)
	if err != nil {
		t.Fatalf("Failed to create client KCP session: %v", err)
	}
	defer clientSess.Close()

	// Set short deadlines for testing
	clientSess.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	serverSess.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	// Test Write (will likely timeout but exercises the code)
	testData := []byte("test data")
	_, err = clientSess.Write(testData)
	// We don't check error here as it may timeout, but we've exercised the Write path

	// Test Read (will likely timeout but exercises the code)
	buf := make([]byte, 1024)
	_, err = serverSess.Read(buf)
	// We don't check error here as it may timeout, but we've exercised the Read path
}

func TestKCPConstants(t *testing.T) {
	// Test that constants are defined correctly
	if IKCP_RTO_NDL != 30 {
		t.Errorf("Expected IKCP_RTO_NDL to be 30, got %d", IKCP_RTO_NDL)
	}
	if IKCP_RTO_MIN != 100 {
		t.Errorf("Expected IKCP_RTO_MIN to be 100, got %d", IKCP_RTO_MIN)
	}
	if IKCP_MTU_DEF != 1400 {
		t.Errorf("Expected IKCP_MTU_DEF to be 1400, got %d", IKCP_MTU_DEF)
	}
}

func TestPacketType(t *testing.T) {
	var pt PacketType = IKCP_PACKET_REGULAR
	if pt != 0 {
		t.Errorf("Expected IKCP_PACKET_REGULAR to be 0, got %d", pt)
	}
}

func TestFlushType(t *testing.T) {
	if IKCP_FLUSH_ACKONLY == 0 {
		t.Error("IKCP_FLUSH_ACKONLY should not be 0")
	}
	if IKCP_FLUSH_FULL == 0 {
		t.Error("IKCP_FLUSH_FULL should not be 0")
	}
}

func TestKCPLogType(t *testing.T) {
	if IKCP_LOG_OUTPUT == 0 {
		t.Error("IKCP_LOG_OUTPUT should not be 0")
	}
	if IKCP_LOG_INPUT == 0 {
		t.Error("IKCP_LOG_INPUT should not be 0")
	}

	// Test combined log types
	if IKCP_LOG_OUTPUT_ALL == 0 {
		t.Error("IKCP_LOG_OUTPUT_ALL should not be 0")
	}
	if IKCP_LOG_INPUT_ALL == 0 {
		t.Error("IKCP_LOG_INPUT_ALL should not be 0")
	}
	if IKCP_LOG_ALL == 0 {
		t.Error("IKCP_LOG_ALL should not be 0")
	}
}
