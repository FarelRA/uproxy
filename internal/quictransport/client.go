package quictransport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

var (
	// ErrConnectionClosed is returned when attempting to use a closed connection
	ErrConnectionClosed = errors.New("connection closed")
	// ErrConnectionNil is returned when the connection is nil
	ErrConnectionNil = errors.New("connection is nil")
)

// Client manages a QUIC client connection with thread-safe access.
type Client struct {
	mu         sync.RWMutex
	conn       *quic.Conn
	serverAddr net.Addr
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewClient creates a new QUIC client but does not establish a connection.
// Call Connect() to establish the connection.
func NewClient(serverAddr net.Addr, tlsConfig *tls.Config, quicConfig *quic.Config) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		serverAddr: serverAddr,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Connect establishes a QUIC connection to the server.
// It creates a UDP socket and dials the server using QUIC.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return errors.New("already connected")
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}

	conn, err := quic.Dial(ctx, udpConn, c.serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	c.conn = conn
	return nil
}

// GetConnection returns the current QUIC connection.
// Returns nil if not connected.
func (c *Client) GetConnection() *quic.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}

// IsConnected returns true if the client has an active connection.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil
}

// OpenTCPStream opens a new QUIC stream for TCP traffic.
// It writes the TCP stream type byte and returns a net.Conn wrapper.
func (c *Client) OpenTCPStream(ctx context.Context) (net.Conn, error) {
	conn := c.GetConnection()
	if conn == nil {
		return nil, ErrConnectionNil
	}

	return OpenTypedStream(ctx, conn, StreamTypeTCP)
}

// OpenUDPStream opens a new QUIC stream for UDP traffic.
// It writes the UDP stream type byte and returns a net.Conn wrapper.
func (c *Client) OpenUDPStream(ctx context.Context) (net.Conn, error) {
	conn := c.GetConnection()
	if conn == nil {
		return nil, ErrConnectionNil
	}

	return OpenTypedStream(ctx, conn, StreamTypeUDP)
}

// OpenTUNStream opens a new QUIC stream for TUN traffic.
// It writes the TUN stream type byte and returns a net.Conn wrapper.
func (c *Client) OpenTUNStream(ctx context.Context) (net.Conn, error) {
	conn := c.GetConnection()
	if conn == nil {
		return nil, ErrConnectionNil
	}

	return OpenTypedStream(ctx, conn, StreamTypeTUN)
}

// WaitForDisconnection blocks until the connection is closed.
// Returns nil if the connection closes normally, or an error if the context is cancelled.
func (c *Client) WaitForDisconnection(ctx context.Context) error {
	conn := c.GetConnection()
	if conn == nil {
		return ErrConnectionNil
	}

	select {
	case <-conn.Context().Done():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close closes the QUIC connection gracefully with error code 0.
func (c *Client) Close() error {
	return c.CloseWithError(0, "client shutdown")
}

// CloseWithError closes the QUIC connection with a specific error code and message.
func (c *Client) CloseWithError(code quic.ApplicationErrorCode, message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	err := c.conn.CloseWithError(code, message)
	c.conn = nil
	c.cancel()

	return err
}

// LocalAddr returns the local address of the connection.
// Returns nil if not connected.
func (c *Client) LocalAddr() net.Addr {
	conn := c.GetConnection()
	if conn == nil {
		return nil
	}
	return conn.LocalAddr()
}

// RemoteAddr returns the remote address of the connection.
func (c *Client) RemoteAddr() net.Addr {
	return c.serverAddr
}

// ConnectionState returns the TLS connection state.
// Returns an empty ConnectionState if not connected.
func (c *Client) ConnectionState() quic.ConnectionState {
	conn := c.GetConnection()
	if conn == nil {
		return quic.ConnectionState{}
	}
	return conn.ConnectionState()
}

// Context returns the client's context.
func (c *Client) Context() context.Context {
	return c.ctx
}
