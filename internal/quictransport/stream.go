package quictransport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// Stream type constants - first byte sent on every stream to identify its purpose
const (
	StreamTypeTCP byte = 0x01 // TCP SOCKS5 connection
	StreamTypeUDP byte = 0x02 // UDP SOCKS5 association
	StreamTypeTUN byte = 0x03 // TUN device tunnel
)

var (
	// ErrInvalidStreamType is returned when an unknown stream type byte is encountered
	ErrInvalidStreamType = errors.New("invalid stream type")
	// ErrStreamTypeMismatch is returned when the expected stream type doesn't match
	ErrStreamTypeMismatch = errors.New("stream type mismatch")
)

// StreamWrapper wraps a quic.Stream and implements the net.Conn interface.
// This allows QUIC streams to be used anywhere a net.Conn is expected.
type StreamWrapper struct {
	stream     *quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewStreamWrapper creates a new StreamWrapper from a QUIC stream.
// The local and remote addresses are taken from the underlying QUIC connection.
func NewStreamWrapper(stream *quic.Stream, localAddr, remoteAddr net.Addr) *StreamWrapper {
	return &StreamWrapper{
		stream:     stream,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// Read reads data from the stream.
func (sw *StreamWrapper) Read(b []byte) (n int, err error) {
	return sw.stream.Read(b)
}

// Write writes data to the stream.
func (sw *StreamWrapper) Write(b []byte) (n int, err error) {
	return sw.stream.Write(b)
}

// Close closes the stream.
func (sw *StreamWrapper) Close() error {
	return sw.stream.Close()
}

// LocalAddr returns the local network address.
func (sw *StreamWrapper) LocalAddr() net.Addr {
	return sw.localAddr
}

// RemoteAddr returns the remote network address.
func (sw *StreamWrapper) RemoteAddr() net.Addr {
	return sw.remoteAddr
}

// SetDeadline sets the read and write deadlines.
func (sw *StreamWrapper) SetDeadline(t time.Time) error {
	return sw.stream.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (sw *StreamWrapper) SetReadDeadline(t time.Time) error {
	return sw.stream.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
func (sw *StreamWrapper) SetWriteDeadline(t time.Time) error {
	return sw.stream.SetWriteDeadline(t)
}

// WriteStreamType writes the stream type byte as the first byte on the stream.
// This must be called immediately after opening a stream.
func WriteStreamType(stream *quic.Stream, streamType byte) error {
	if streamType != StreamTypeTCP && streamType != StreamTypeUDP && streamType != StreamTypeTUN {
		return fmt.Errorf("%w: 0x%02x", ErrInvalidStreamType, streamType)
	}

	_, err := stream.Write([]byte{streamType})
	if err != nil {
		return fmt.Errorf("failed to write stream type: %w", err)
	}

	return nil
}

// ReadStreamType reads the stream type byte from the stream.
// This must be called immediately after accepting a stream.
func ReadStreamType(stream *quic.Stream) (byte, error) {
	buf := make([]byte, 1)
	_, err := io.ReadFull(stream, buf)
	if err != nil {
		return 0, fmt.Errorf("failed to read stream type: %w", err)
	}

	streamType := buf[0]
	if streamType != StreamTypeTCP && streamType != StreamTypeUDP && streamType != StreamTypeTUN {
		return 0, fmt.Errorf("%w: 0x%02x", ErrInvalidStreamType, streamType)
	}

	return streamType, nil
}

// OpenTypedStream opens a new QUIC stream and writes the stream type byte.
// Returns a StreamWrapper that implements net.Conn.
func OpenTypedStream(ctx context.Context, conn *quic.Conn, streamType byte) (net.Conn, error) {
	if streamType != StreamTypeTCP && streamType != StreamTypeUDP && streamType != StreamTypeTUN {
		return nil, fmt.Errorf("%w: 0x%02x", ErrInvalidStreamType, streamType)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	if err := WriteStreamType(stream, streamType); err != nil {
		stream.Close()
		return nil, err
	}

	wrapper := NewStreamWrapper(stream, conn.LocalAddr(), conn.RemoteAddr())
	return wrapper, nil
}

// AcceptTypedStream accepts a QUIC stream and reads the stream type byte.
// Returns the stream type and a StreamWrapper that implements net.Conn.
func AcceptTypedStream(conn *quic.Conn) (byte, net.Conn, error) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return 0, nil, fmt.Errorf("failed to accept stream: %w", err)
	}

	streamType, err := ReadStreamType(stream)
	if err != nil {
		stream.Close()
		return 0, nil, err
	}

	wrapper := NewStreamWrapper(stream, conn.LocalAddr(), conn.RemoteAddr())
	return streamType, wrapper, nil
}

// StreamTypeString returns a human-readable string for the stream type.
func StreamTypeString(streamType byte) string {
	switch streamType {
	case StreamTypeTCP:
		return "TCP"
	case StreamTypeUDP:
		return "UDP"
	case StreamTypeTUN:
		return "TUN"
	default:
		return fmt.Sprintf("Unknown(0x%02x)", streamType)
	}
}
