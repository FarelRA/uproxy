package socks5

import (
	"encoding/binary"
	"io"
)

// SSH Channel names used for multiplexing
const (
	ChannelTypeTCP = "socks5-tcp"
	ChannelTypeUDP = "socks5-udp"
)

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
