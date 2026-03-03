package uproxy

import (
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ChannelConn wraps an ssh.Channel to perfectly implement the standard net.Conn interface.
// It also holds logical local and remote addresses for accurate proxy routing metrics.
type ChannelConn struct {
	ssh.Channel
	localAddr     net.Addr
	remoteAddr    net.Addr
	readDeadline  time.Time
	writeDeadline time.Time
	mu            sync.Mutex
}

// timeoutError implements net.Error for timeout operations
type timeoutError struct{}

func (e timeoutError) Error() string   { return "i/o timeout" }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

// NewChannelConn constructs a standard net.Conn compatible wrapper around an SSH channel.
func NewChannelConn(channel ssh.Channel, local, remote net.Addr) *ChannelConn {
	return &ChannelConn{
		Channel:    channel,
		localAddr:  local,
		remoteAddr: remote,
	}
}

// LocalAddr returns the logical local address of the underlying tunnel.
func (c *ChannelConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the logical remote address of the underlying tunnel.
func (c *ChannelConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline sets both read and write deadlines for the connection.
func (c *ChannelConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline sets the read deadline for the connection.
func (c *ChannelConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

// SetWriteDeadline sets the write deadline for the connection.
func (c *ChannelConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

// Read reads data from the channel with deadline support.
func (c *ChannelConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()

	if deadline.IsZero() {
		return c.Channel.Read(b)
	}

	timeout := time.Until(deadline)
	if timeout <= 0 {
		return 0, &net.OpError{Op: "read", Net: "ssh", Err: timeoutError{}}
	}

	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)

	go func() {
		n, err := c.Channel.Read(b)
		ch <- result{n, err}
	}()

	select {
	case res := <-ch:
		return res.n, res.err
	case <-time.After(timeout):
		return 0, &net.OpError{Op: "read", Net: "ssh", Err: timeoutError{}}
	}
}

// Write writes data to the channel with deadline support.
func (c *ChannelConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()

	if deadline.IsZero() {
		return c.Channel.Write(b)
	}

	timeout := time.Until(deadline)
	if timeout <= 0 {
		return 0, &net.OpError{Op: "write", Net: "ssh", Err: timeoutError{}}
	}

	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)

	go func() {
		n, err := c.Channel.Write(b)
		ch <- result{n, err}
	}()

	select {
	case res := <-ch:
		return res.n, res.err
	case <-time.After(timeout):
		return 0, &net.OpError{Op: "write", Net: "ssh", Err: timeoutError{}}
	}
}
