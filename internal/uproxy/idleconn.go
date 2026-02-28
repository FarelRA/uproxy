package uproxy

import (
	"net"
	"time"
)

// IdleTimeoutConn wraps a standard net.Conn and automatically extends its
// Read and Write deadlines upon every successful IO operation. This implements
// a rolling idle timeout, ensuring inactive connections are forcefully closed
// without terminating actively used long-lived connections.
type IdleTimeoutConn struct {
	net.Conn
	idleTimeout time.Duration
}

// NewIdleTimeoutConn creates a new rolling timeout wrapper around the given connection.
func NewIdleTimeoutConn(conn net.Conn, timeout time.Duration) *IdleTimeoutConn {
	return &IdleTimeoutConn{
		Conn:        conn,
		idleTimeout: timeout,
	}
}

// Read reads data from the connection and pushes the read deadline forward.
func (c *IdleTimeoutConn) Read(b []byte) (n int, err error) {
	if c.idleTimeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idleTimeout))
	}
	return c.Conn.Read(b)
}

// Write writes data to the connection and pushes the write deadline forward.
func (c *IdleTimeoutConn) Write(b []byte) (n int, err error) {
	if c.idleTimeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idleTimeout))
	}
	return c.Conn.Write(b)
}
