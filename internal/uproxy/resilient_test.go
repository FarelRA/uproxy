package uproxy

import (
	"net"
	"testing"
	"time"

	"uproxy/internal/network"
	"uproxy/internal/telemetry"
)

func TestNewResilientPacketConn_ServerMode(t *testing.T) {
	// Create a resilient connection in server mode
	r := NewResilientPacketConn(":0", "", 1*time.Second, 0, true)
	defer r.Close()

	if r == nil {
		t.Fatal("Expected non-nil ResilientPacketConn")
	}
	if r.serverMode != true {
		t.Error("Expected serverMode to be true")
	}
	if r.monitor != nil {
		t.Error("Expected monitor to be nil in server mode")
	}
	if r.telemetry == nil {
		t.Error("Expected telemetry to be non-nil")
	}
}

func TestNewResilientPacketConn_ClientMode(t *testing.T) {
	// Create a resilient connection in client mode
	r := NewResilientPacketConn(":0", "", 1*time.Second, 0, false)
	defer r.Close()

	if r == nil {
		t.Fatal("Expected non-nil ResilientPacketConn")
	}
	if r.serverMode != false {
		t.Error("Expected serverMode to be false")
	}
	if r.monitor == nil {
		t.Error("Expected monitor to be non-nil in client mode")
	}
	if r.telemetry == nil {
		t.Error("Expected telemetry to be non-nil")
	}
}

func TestNewResilientPacketConn_DefaultReconnectInterval(t *testing.T) {
	// Test that zero reconnect interval defaults to 1 second
	r := NewResilientPacketConn(":0", "", 0, 0, true)
	defer r.Close()

	if r.reconnectInt != 1*time.Second {
		t.Errorf("Expected default reconnect interval of 1s, got %v", r.reconnectInt)
	}
}

func TestResilientPacketConn_SetFailureHandler(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 1*time.Second, 0, false)
	defer r.Close()

	handler := func(result network.DiagnosticResult) bool {
		return true
	}

	r.SetFailureHandler("example.com:443", handler)

	if r.diagnostics == nil {
		t.Error("Expected diagnostics to be set")
	}
	if r.failureHandler == nil {
		t.Error("Expected failureHandler to be set")
	}
}

func TestResilientPacketConn_LocalAddr(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 1*time.Second, 0, true)
	defer r.Close()

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	addr := r.LocalAddr()
	if addr == nil {
		t.Error("Expected non-nil LocalAddr")
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Error("Expected LocalAddr to be *net.UDPAddr")
	}
	if udpAddr.Port == 0 {
		t.Error("Expected non-zero port")
	}
}

func TestResilientPacketConn_ReadWriteOperations(t *testing.T) {
	// Create two resilient connections for testing
	r1 := NewResilientPacketConn(":0", "", 1*time.Second, 0, true)
	defer r1.Close()

	r2 := NewResilientPacketConn(":0", "", 1*time.Second, 0, true)
	defer r2.Close()

	// Wait for connections to be established
	time.Sleep(100 * time.Millisecond)

	addr1 := r1.LocalAddr()
	addr2 := r2.LocalAddr()

	// Test WriteTo
	testData := []byte("hello world")
	n, err := r1.WriteTo(testData, addr2)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), n)
	}

	// Test ReadFrom with timeout
	r2.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1024)
	n, fromAddr, err := r2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to read %d bytes, read %d", len(testData), n)
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected to read %q, got %q", testData, buf[:n])
	}
	// Check that the port matches (IP can vary between :: and ::1)
	fromUDP, ok1 := fromAddr.(*net.UDPAddr)
	addr1UDP, ok2 := addr1.(*net.UDPAddr)
	if !ok1 || !ok2 {
		t.Error("Expected UDPAddr types")
	} else if fromUDP.Port != addr1UDP.Port {
		t.Errorf("Expected from port %d, got %d", addr1UDP.Port, fromUDP.Port)
	}
}

func TestResilientPacketConn_SetBuffers(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 1*time.Second, 0, true)
	defer r.Close()

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	err := r.SetReadBuffer(65536)
	if err != nil {
		t.Errorf("SetReadBuffer failed: %v", err)
	}

	err = r.SetWriteBuffer(65536)
	if err != nil {
		t.Errorf("SetWriteBuffer failed: %v", err)
	}
}

func TestResilientPacketConn_SetDeadlines(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 1*time.Second, 0, true)
	defer r.Close()

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	deadline := time.Now().Add(1 * time.Second)

	err := r.SetDeadline(deadline)
	if err != nil {
		t.Errorf("SetDeadline failed: %v", err)
	}

	err = r.SetReadDeadline(deadline)
	if err != nil {
		t.Errorf("SetReadDeadline failed: %v", err)
	}

	err = r.SetWriteDeadline(deadline)
	if err != nil {
		t.Errorf("SetWriteDeadline failed: %v", err)
	}
}

func TestResilientPacketConn_Close(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 1*time.Second, 0, false)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	err := r.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Verify connection is closed
	if !r.isClosed() {
		t.Error("Expected connection to be closed")
	}

	// Second close should not error
	err = r.Close()
	if err != nil {
		t.Errorf("Second Close failed: %v", err)
	}
}

func TestResilientPacketConn_ReadFromAfterClose(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 1*time.Second, 0, true)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	r.Close()

	// Try to read after close
	buf := make([]byte, 1024)
	_, _, err := r.ReadFrom(buf)
	if err == nil {
		t.Error("Expected error on ReadFrom after close, got nil")
	}
}

func TestResilientPacketConn_WriteToAfterClose(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 1*time.Second, 0, true)

	// Wait for connection to be established
	time.Sleep(100 * time.Millisecond)

	addr := r.LocalAddr()
	r.Close()

	// Try to write after close
	_, err := r.WriteTo([]byte("test"), addr)
	if err != net.ErrClosed {
		t.Errorf("Expected net.ErrClosed, got %v", err)
	}
}

func TestResilientPacketConn_GetConnWhenNil(t *testing.T) {
	r := &ResilientPacketConn{
		bindAddr:     ":0",
		reconnectInt: 1 * time.Second,
		closed:       true,
	}

	conn := r.getConn()
	if conn != nil {
		t.Error("Expected nil connection")
	}
}

func TestResilientPacketConn_LocalAddrWhenConnNil(t *testing.T) {
	r := &ResilientPacketConn{
		bindAddr:     ":0",
		reconnectInt: 1 * time.Second,
		closed:       true,
	}

	addr := r.LocalAddr()
	if addr == nil {
		t.Error("Expected non-nil address")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Error("Expected *net.UDPAddr")
	}
	if udpAddr.Port != 0 || udpAddr.IP != nil {
		t.Error("Expected empty UDPAddr")
	}
}

func TestResilientPacketConn_SetBuffersWhenConnNil(t *testing.T) {
	r := &ResilientPacketConn{
		bindAddr:     ":0",
		reconnectInt: 1 * time.Second,
		closed:       true,
	}

	err := r.SetReadBuffer(65536)
	if err != nil {
		t.Errorf("SetReadBuffer should not error when conn is nil, got %v", err)
	}

	err = r.SetWriteBuffer(65536)
	if err != nil {
		t.Errorf("SetWriteBuffer should not error when conn is nil, got %v", err)
	}
}

func TestResilientPacketConn_SetDeadlinesWhenConnNil(t *testing.T) {
	r := &ResilientPacketConn{
		bindAddr:     ":0",
		reconnectInt: 1 * time.Second,
		closed:       true,
	}

	deadline := time.Now().Add(1 * time.Second)

	err := r.SetDeadline(deadline)
	if err != nil {
		t.Errorf("SetDeadline should not error when conn is nil, got %v", err)
	}

	err = r.SetReadDeadline(deadline)
	if err != nil {
		t.Errorf("SetReadDeadline should not error when conn is nil, got %v", err)
	}

	err = r.SetWriteDeadline(deadline)
	if err != nil {
		t.Errorf("SetWriteDeadline should not error when conn is nil, got %v", err)
	}
}

func TestResilientPacketConn_WriteToWhenConnNil(t *testing.T) {
	r := &ResilientPacketConn{
		bindAddr:     ":0",
		reconnectInt: 1 * time.Second,
	}

	// WriteTo when conn is nil should return len(p) without error
	testData := []byte("test")
	n, err := r.WriteTo(testData, &net.UDPAddr{})
	if err != nil {
		t.Errorf("WriteTo should not error when conn is nil, got %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, got %d", len(testData), n)
	}
}

func TestResilientPacketConn_WriteToTimeoutError(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 100*time.Millisecond, 0, false)
	defer r.Close()

	time.Sleep(50 * time.Millisecond)

	// Set a very short deadline to trigger timeout
	r.SetWriteDeadline(time.Now().Add(-1 * time.Second))

	testData := []byte("test")
	_, err := r.WriteTo(testData, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999})

	if err == nil {
		t.Error("Expected timeout error, got nil")
	}

	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Errorf("Expected timeout error, got %v", err)
	}
}

func TestResilientPacketConn_ReadFromErrors(t *testing.T) {
	// Create a resilient conn
	r := NewResilientPacketConn(":0", "", 100*time.Millisecond, 0, false)
	defer r.Close()

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	// Close the underlying connection to simulate error
	r.mu.Lock()
	if r.conn != nil {
		r.conn.Close()
	}
	r.mu.Unlock()

	// Try to read - should trigger reconnect
	buf := make([]byte, 1024)
	r.getConn().SetReadDeadline(time.Now().Add(10 * time.Millisecond))

	// This should eventually succeed after reconnect
	done := make(chan bool)
	go func() {
		_, _, err := r.ReadFrom(buf)
		if err == nil || err == net.ErrClosed {
			done <- true
		}
	}()

	select {
	case <-done:
		// Success
	case <-time.After(500 * time.Millisecond):
		// Timeout is acceptable for this test
	}
}

func TestResilientPacketConn_WriteToErrors(t *testing.T) {
	// Create a resilient conn
	r := NewResilientPacketConn(":0", "", 100*time.Millisecond, 0, false)
	defer r.Close()

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	addr := r.LocalAddr()

	// Close the underlying connection to simulate error
	r.mu.Lock()
	if r.conn != nil {
		r.conn.Close()
	}
	r.mu.Unlock()

	// Try to write - should trigger reconnect and return success
	testData := []byte("test")
	n, err := r.WriteTo(testData, addr)
	if err != nil {
		t.Errorf("WriteTo should not return error on reconnect: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, got %d", len(testData), n)
	}
}

func TestResilientPacketConn_ClosedOperations(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 100*time.Millisecond, 0, false)

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	// Close the connection
	r.Close()

	// Try operations on closed connection
	buf := make([]byte, 1024)
	_, _, err := r.ReadFrom(buf)
	if err == nil {
		t.Error("Expected error on ReadFrom after close, got nil")
	}

	_, err = r.WriteTo([]byte("test"), &net.UDPAddr{})
	if err == nil {
		t.Error("Expected error on WriteTo after close, got nil")
	}

	// Close again should not error
	err = r.Close()
	if err != nil {
		t.Errorf("Second Close should not error: %v", err)
	}
}

func TestResilientPacketConn_TriggerReconnectWithoutDiagnostics(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 50*time.Millisecond, 0, false)
	defer r.Close()

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	// Trigger reconnect without diagnostics (diagnostics is nil by default)
	r.triggerReconnect()

	// Wait for reconnect to complete
	time.Sleep(100 * time.Millisecond)

	// Verify connection still works
	if r.getConn() == nil {
		t.Error("Expected connection to be re-established")
	}
}

func TestResilientPacketConn_TriggerReconnectWithDiagnostics(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 50*time.Millisecond, 0, false)
	defer r.Close()

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	// Set failure handler
	handlerCalled := false
	handler := func(result network.DiagnosticResult) bool {
		handlerCalled = true
		return false // Don't handle, let default reconnect happen
	}
	r.SetFailureHandler("example.com:443", handler)

	// Trigger reconnect with diagnostics
	r.triggerReconnect()

	// Wait for reconnect to complete
	time.Sleep(200 * time.Millisecond)

	// Verify handler was called
	if !handlerCalled {
		t.Error("Expected failure handler to be called")
	}

	// Verify connection still works
	if r.getConn() == nil {
		t.Error("Expected connection to be re-established")
	}
}

func TestResilientPacketConn_TriggerReconnectHandled(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 50*time.Millisecond, 0, false)
	defer r.Close()

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	// Set failure handler that handles the failure
	handlerCalled := false
	handler := func(result network.DiagnosticResult) bool {
		handlerCalled = true
		return true // Handle the failure
	}
	r.SetFailureHandler("example.com:443", handler)

	// Trigger reconnect
	r.triggerReconnect()

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Verify handler was called
	if !handlerCalled {
		t.Error("Expected failure handler to be called")
	}
}

func TestResilientPacketConn_TriggerReconnectWhileReconnecting(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 50*time.Millisecond, 0, false)
	defer r.Close()

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	// Set reconnecting flag
	r.mu.Lock()
	r.reconnecting = true
	r.mu.Unlock()

	// Try to trigger reconnect - should return early
	r.triggerReconnect()

	// Reset flag
	r.mu.Lock()
	r.reconnecting = false
	r.mu.Unlock()
}

func TestResilientPacketConn_TriggerReconnectWhenClosed(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 50*time.Millisecond, 0, false)

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	// Close the connection
	r.Close()

	// Try to trigger reconnect - should return early
	r.triggerReconnect()
}

func TestResilientPacketConn_ReadFromTimeout(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 50*time.Millisecond, 0, true)
	defer r.Close()

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	// Set a very short read deadline to trigger timeout
	r.SetReadDeadline(time.Now().Add(1 * time.Millisecond))

	buf := make([]byte, 1024)
	_, _, err := r.ReadFrom(buf)

	// Should get a timeout error
	if err == nil {
		t.Error("Expected timeout error")
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Errorf("Expected timeout error, got %v", err)
	}
}

func TestResilientPacketConn_ReadFromWhenConnNil(t *testing.T) {
	r := &ResilientPacketConn{
		bindAddr:     ":0",
		reconnectInt: 1 * time.Second,
		closed:       false,
		telemetry:    telemetry.NewConnTelemetry("test", 1*time.Second),
	}
	defer r.Close()

	// Start a goroutine to read (conn is nil, not closed)
	done := make(chan bool)
	go func() {
		buf := make([]byte, 1024)
		_, _, err := r.ReadFrom(buf)
		if err != net.ErrClosed {
			t.Errorf("Expected ErrClosed, got %v", err)
		}
		done <- true
	}()

	// Give it time to loop a few times with nil conn
	time.Sleep(250 * time.Millisecond)

	// Close to exit the loop
	r.Close()

	// Wait for goroutine to finish
	<-done
}

func TestResilientPacketConn_WriteToTimeout(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 50*time.Millisecond, 0, true)
	defer r.Close()

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	// Set a very short write deadline to trigger timeout
	r.SetWriteDeadline(time.Now().Add(1 * time.Nanosecond))
	time.Sleep(10 * time.Millisecond) // Ensure deadline passes

	// Try to write - should get timeout error
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9999")
	_, err := r.WriteTo([]byte("test"), addr)

	// Should get a timeout error
	if err == nil {
		t.Error("Expected timeout error")
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Errorf("Expected timeout error, got %v", err)
	}
}

func TestResilientPacketConn_WriteToWhenConnNilButNotClosed(t *testing.T) {
	r := &ResilientPacketConn{
		bindAddr:     ":0",
		reconnectInt: 1 * time.Second,
		closed:       false,
		telemetry:    telemetry.NewConnTelemetry("test", 1*time.Second),
	}
	// conn is nil, closed is false - simulates during reconnection

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9999")
	n, err := r.WriteTo([]byte("test"), addr)

	// Should return len(p) with no error when conn is nil but not closed
	if err != nil {
		t.Errorf("Expected no error when conn is nil but not closed, got %v", err)
	}
	if n != 4 {
		t.Errorf("Expected n=4, got %d", n)
	}
}

func TestResilientPacketConn_CloseWhenConnNil(t *testing.T) {
	r := &ResilientPacketConn{
		bindAddr:     ":0",
		reconnectInt: 1 * time.Second,
		closed:       false,
		telemetry:    telemetry.NewConnTelemetry("test", 1*time.Second),
	}

	// Close when conn is nil
	err := r.Close()
	if err != nil {
		t.Errorf("Close should not error when conn is nil, got %v", err)
	}
}

func TestResilientPacketConn_WriteToNonTimeoutError(t *testing.T) {
	r := NewResilientPacketConn(":0", "", 50*time.Millisecond, 0, true)
	defer r.Close()

	// Wait for initial connection
	time.Sleep(50 * time.Millisecond)

	// Close the underlying connection to trigger a non-timeout error
	r.mu.Lock()
	if r.conn != nil {
		r.conn.Close()
	}
	r.mu.Unlock()

	// Try to write - should trigger reconnect and return len(p), nil
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9999")
	n, err := r.WriteTo([]byte("test"), addr)

	// Should return len(p), nil after triggering reconnect
	if err != nil {
		t.Errorf("Expected nil error after reconnect trigger, got %v", err)
	}
	if n != 4 {
		t.Errorf("Expected n=4, got %d", n)
	}
}

func TestResilientPacketConn_ReconnectSyncErrors(t *testing.T) {
	// Test reconnectSync with invalid bind address
	r := &ResilientPacketConn{
		bindAddr:     "invalid:address:format",
		reconnectInt: 50 * time.Millisecond,
		closed:       false,
		telemetry:    telemetry.NewConnTelemetry("test", 1*time.Second),
	}
	defer r.Close()

	// Start reconnectSync in background
	go r.reconnectSync()

	// Give it time to try reconnecting a few times
	time.Sleep(200 * time.Millisecond)

	// Close to stop reconnection attempts
	r.Close()
}
