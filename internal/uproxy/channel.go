package uproxy

import (
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// ChannelConn wraps an ssh.Channel to perfectly implement the standard net.Conn interface.
// It also holds logical local and remote addresses for accurate proxy routing metrics.
type ChannelConn struct {
	ssh.Channel
	localAddr  net.Addr
	remoteAddr net.Addr
}

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

// SetDeadline is a no-op as SSH channels do not natively support IO deadlines.
// The underlying SSH protocol handles timeouts at the transport layer.
// This method exists to satisfy the net.Conn interface.
func (c *ChannelConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline is a no-op for SSH channels.
// The underlying SSH protocol handles timeouts at the transport layer.
// This method exists to satisfy the net.Conn interface.
func (c *ChannelConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline is a no-op for SSH channels.
// The underlying SSH protocol handles timeouts at the transport layer.
// This method exists to satisfy the net.Conn interface.
func (c *ChannelConn) SetWriteDeadline(t time.Time) error {
	return nil
}
