package quictransport

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// ConnectionState represents the state of a QUIC connection.
type ConnectionState int

const (
	// StateConnecting indicates the connection is being established
	StateConnecting ConnectionState = iota
	// StateConnected indicates the connection is established and active
	StateConnected
	// StateDisconnected indicates the connection was lost
	StateDisconnected
	// StateClosed indicates the connection was explicitly closed
	StateClosed
)

// String returns a human-readable string representation of the connection state.
func (s ConnectionState) String() string {
	switch s {
	case StateConnecting:
		return "Connecting"
	case StateConnected:
		return "Connected"
	case StateDisconnected:
		return "Disconnected"
	case StateClosed:
		return "Closed"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// ConnectionInfo holds metadata about a QUIC connection.
type ConnectionInfo struct {
	LocalAddr      net.Addr
	RemoteAddr     net.Addr
	ConnectedAt    time.Time
	LastActivityAt time.Time
	State          ConnectionState
}

// NewConnectionInfo creates a new ConnectionInfo from a QUIC connection.
func NewConnectionInfo(conn *quic.Conn) *ConnectionInfo {
	now := time.Now()
	return &ConnectionInfo{
		LocalAddr:      conn.LocalAddr(),
		RemoteAddr:     conn.RemoteAddr(),
		ConnectedAt:    now,
		LastActivityAt: now,
		State:          StateConnected,
	}
}

// UpdateActivity updates the last activity timestamp.
func (ci *ConnectionInfo) UpdateActivity() {
	ci.LastActivityAt = time.Now()
}

// IdleDuration returns how long the connection has been idle.
func (ci *ConnectionInfo) IdleDuration() time.Duration {
	return time.Since(ci.LastActivityAt)
}

// ConnectionDuration returns how long the connection has been active.
func (ci *ConnectionInfo) ConnectionDuration() time.Duration {
	return time.Since(ci.ConnectedAt)
}

// GetConnectionStats returns statistics about a QUIC connection.
func GetConnectionStats(conn *quic.Conn) quic.ConnectionStats {
	if conn == nil {
		return quic.ConnectionStats{}
	}
	return conn.ConnectionStats()
}

// Supports0RTT checks if the connection supports 0-RTT.
func Supports0RTT(conn *quic.Conn) bool {
	if conn == nil {
		return false
	}
	state := conn.ConnectionState()
	return state.Used0RTT
}

// IsHandshakeComplete checks if the TLS handshake is complete.
func IsHandshakeComplete(conn *quic.Conn) bool {
	if conn == nil {
		return false
	}
	select {
	case <-conn.HandshakeComplete():
		return true
	default:
		return false
	}
}

// WaitForHandshake waits for the TLS handshake to complete.
func WaitForHandshake(conn *quic.Conn) {
	if conn == nil {
		return
	}
	<-conn.HandshakeComplete()
}

// IsTemporaryError determines if an error is temporary and the operation can be retried.
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Temporary()
	}

	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return false
	}

	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return false
	}

	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		return false
	}

	var idleErr *quic.IdleTimeoutError
	if errors.As(err, &idleErr) {
		return false
	}

	return true
}

// ExtractErrorCode extracts the application error code from a QUIC error.
// Returns 0 if the error is not an ApplicationError.
func ExtractErrorCode(err error) quic.ApplicationErrorCode {
	if err == nil {
		return 0
	}

	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.ErrorCode
	}

	return 0
}

// ExtractErrorMessage extracts a human-readable error message from a QUIC error.
func ExtractErrorMessage(err error) string {
	if err == nil {
		return ""
	}

	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.ErrorMessage
	}

	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		return transportErr.ErrorMessage
	}

	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		return fmt.Sprintf("stream error: code=%d", streamErr.ErrorCode)
	}

	var idleErr *quic.IdleTimeoutError
	if errors.As(err, &idleErr) {
		return "idle timeout"
	}

	return err.Error()
}

// FormatConnectionInfo formats connection information for logging.
func FormatConnectionInfo(conn *quic.Conn) string {
	if conn == nil {
		return "connection=nil"
	}

	state := conn.ConnectionState()
	return fmt.Sprintf("local=%s remote=%s tls_version=%s cipher_suite=%s",
		conn.LocalAddr(),
		conn.RemoteAddr(),
		tlsVersionString(state.TLS.Version),
		tlsCipherSuiteString(state.TLS.CipherSuite))
}

// FormatStreamInfo formats stream information for logging.
func FormatStreamInfo(streamType byte, streamID uint64) string {
	return fmt.Sprintf("type=%s stream_id=%d", StreamTypeString(streamType), streamID)
}

// tlsVersionString returns a human-readable TLS version string.
func tlsVersionString(version uint16) string {
	switch version {
	case 0x0304:
		return "TLS1.3"
	case 0x0303:
		return "TLS1.2"
	case 0x0302:
		return "TLS1.1"
	case 0x0301:
		return "TLS1.0"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", version)
	}
}

// tlsCipherSuiteString returns a human-readable cipher suite string.
func tlsCipherSuiteString(suite uint16) string {
	switch suite {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", suite)
	}
}
