package framing

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MaxFrameSize is the maximum allowed frame size to prevent memory exhaustion attacks.
	// Set to 16KB as a reasonable limit for packet-based protocols.
	MaxFrameSize = 16384
)

// WriteFramed writes a length-prefixed byte slice to the writer.
// The length is encoded as a 2-byte big-endian uint16, limiting data to 65535 bytes.
// Callers must ensure data length does not exceed this limit before calling.
// Returns an error if data exceeds the maximum frame size.
func WriteFramed(w io.Writer, data []byte) error {
	if len(data) > MaxFrameSize {
		return fmt.Errorf("data too large: %d bytes (max %d)", len(data), MaxFrameSize)
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))

	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}

	_, err := w.Write(data)
	return err
}

// ReadFramed reads a length-prefixed byte slice from the reader.
// The length is decoded from a 2-byte big-endian uint16 prefix.
func ReadFramed(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(lenBuf[:])
	if length == 0 {
		return nil, fmt.Errorf("invalid frame length: 0")
	}
	if length > MaxFrameSize {
		return nil, fmt.Errorf("frame too large: %d bytes (max %d)", length, MaxFrameSize)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	return data, nil
}
