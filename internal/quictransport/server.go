package quictransport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

// Server manages a QUIC server listener with connection tracking.
type Server struct {
	mu            sync.RWMutex
	listener      *quic.Listener
	listenAddr    net.Addr
	tlsConfig     *tls.Config
	quicConfig    *quic.Config
	activeConns   map[*quic.Conn]struct{}
	activeConnsMu sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewServer creates a new QUIC server but does not start listening.
// Call Listen() to start accepting connections.
func NewServer(listenAddr net.Addr, tlsConfig *tls.Config, quicConfig *quic.Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		listenAddr:  listenAddr,
		tlsConfig:   tlsConfig,
		quicConfig:  quicConfig,
		activeConns: make(map[*quic.Conn]struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Listen starts the QUIC listener on the configured address.
// It creates a UDP socket and starts listening for QUIC connections.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listener != nil {
		return fmt.Errorf("already listening")
	}

	udpAddr, ok := s.listenAddr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("listen address must be a UDP address, got %T", s.listenAddr)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}

	listener, err := quic.Listen(udpConn, s.tlsConfig, s.quicConfig)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	s.listener = listener
	return nil
}

// Accept accepts an incoming QUIC connection.
// It blocks until a connection arrives or the context is cancelled.
func (s *Server) Accept(ctx context.Context) (*quic.Conn, error) {
	listener := s.getListener()
	if listener == nil {
		return nil, fmt.Errorf("server not listening")
	}

	conn, err := listener.Accept(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %w", err)
	}

	s.trackConnection(conn)
	return conn, nil
}

// AcceptStream accepts a stream from a connection and reads the stream type.
// Returns the stream type and a net.Conn wrapper.
func (s *Server) AcceptStream(conn *quic.Conn) (byte, net.Conn, error) {
	if conn == nil {
		return 0, nil, ErrConnectionNil
	}

	return AcceptTypedStream(conn)
}

// getListener returns the current listener with read lock.
func (s *Server) getListener() *quic.Listener {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listener
}

// trackConnection adds a connection to the active connections map.
func (s *Server) trackConnection(conn *quic.Conn) {
	s.activeConnsMu.Lock()
	defer s.activeConnsMu.Unlock()
	s.activeConns[conn] = struct{}{}
}

// untrackConnection removes a connection from the active connections map.
func (s *Server) untrackConnection(conn *quic.Conn) {
	s.activeConnsMu.Lock()
	defer s.activeConnsMu.Unlock()
	delete(s.activeConns, conn)
}

// UntrackConnection removes a connection from tracking.
// This should be called when a connection handler completes.
func (s *Server) UntrackConnection(conn *quic.Conn) {
	s.untrackConnection(conn)
}

// ActiveConnectionCount returns the number of active connections.
func (s *Server) ActiveConnectionCount() int {
	s.activeConnsMu.RLock()
	defer s.activeConnsMu.RUnlock()
	return len(s.activeConns)
}

// CloseAllConnections closes all active connections with the given error code and message.
func (s *Server) CloseAllConnections(code quic.ApplicationErrorCode, message string) {
	s.activeConnsMu.Lock()
	conns := make([]*quic.Conn, 0, len(s.activeConns))
	for conn := range s.activeConns {
		conns = append(conns, conn)
	}
	s.activeConnsMu.Unlock()

	for _, conn := range conns {
		conn.CloseWithError(code, message)
	}
}

// Close closes the listener and all active connections.
// It performs graceful shutdown by closing connections first, then the listener.
func (s *Server) Close() error {
	return s.CloseWithError(0, "server shutdown")
}

// CloseWithError closes the listener and all active connections with a specific error.
func (s *Server) CloseWithError(code quic.ApplicationErrorCode, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.CloseAllConnections(code, message)

	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		s.cancel()
		return err
	}

	return nil
}

// Addr returns the listener's network address.
// Returns nil if not listening.
func (s *Server) Addr() net.Addr {
	listener := s.getListener()
	if listener == nil {
		return s.listenAddr
	}
	return listener.Addr()
}

// Context returns the server's context.
func (s *Server) Context() context.Context {
	return s.ctx
}

// IsListening returns true if the server is currently listening.
func (s *Server) IsListening() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listener != nil
}
