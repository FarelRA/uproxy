package socks5

import (
	"encoding/binary"
	"io"

	"uproxy/internal/framing"
)

// SSH Channel names used for multiplexing
const (
	ChannelTypeTCP = "socks5-tcp"
	ChannelTypeUDP = "socks5-udp"
)

// WriteFramed writes a length-prefixed byte slice to the writer
// Deprecated: Use framing.WriteFramed directly
func WriteFramed(w io.Writer, data []byte) error {
	return framing.WriteFramed(w, data)
}

// ReadFramed reads a length-prefixed byte slice from the reader
// Deprecated: Use framing.ReadFramed directly
func ReadFramed(r io.Reader) ([]byte, error) {
	return framing.ReadFramed(r)
}

// WriteTargetHeader writes the target address to the SSH channel during initialization
func WriteTargetHeader(w io.Writer, target string) error {
	targetBytes := []byte(target)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(targetBytes)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(targetBytes)
	return err
}

// ReadTargetHeader reads the target address from the SSH channel during initialization
func ReadTargetHeader(r io.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	targetLen := binary.BigEndian.Uint16(lenBuf[:])
	targetBuf := make([]byte, targetLen)
	if _, err := io.ReadFull(r, targetBuf); err != nil {
		return "", err
	}
	return string(targetBuf), nil
}
