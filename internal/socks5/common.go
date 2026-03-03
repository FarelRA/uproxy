package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

var errTargetHeaderTooLong = errors.New("target header too long")

// SSH Channel names used for multiplexing
const (
	ChannelTypeTCP = "socks5-tcp"
	ChannelTypeUDP = "socks5-udp"
)

// WriteTargetHeader writes the target address to the SSH channel during initialization
func WriteTargetHeader(w io.Writer, target string) error {
	targetBytes := []byte(target)
	if len(targetBytes) > 0xFFFF {
		return errTargetHeaderTooLong
	}
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

// parseSOCKS5Address parses a SOCKS5 address from the given data starting at the specified index.
// It supports IPv4 (atyp=1), domain name (atyp=3), and IPv6 (atyp=4) address types.
// Returns the host string, the new index after parsing, and any error encountered.
func parseSOCKS5Address(data []byte, atyp byte, idx int) (host string, newIdx int, err error) {
	switch atyp {
	case 1: // IPv4
		if len(data) < idx+4 {
			return "", idx, io.ErrUnexpectedEOF
		}
		host = net.IP(data[idx : idx+4]).String()
		newIdx = idx + 4
	case 3: // Domain name
		if len(data) < idx+1 {
			return "", idx, io.ErrUnexpectedEOF
		}
		l := int(data[idx])
		if l == 0 {
			return "", idx, net.InvalidAddrError("empty domain")
		}
		idx++
		if len(data) < idx+l {
			return "", idx, io.ErrUnexpectedEOF
		}
		host = string(data[idx : idx+l])
		newIdx = idx + l
	case 4: // IPv6
		if len(data) < idx+16 {
			return "", idx, io.ErrUnexpectedEOF
		}
		host = net.IP(data[idx : idx+16]).String()
		newIdx = idx + 16
	default:
		return "", idx, net.InvalidAddrError("invalid atyp")
	}
	return host, newIdx, nil
}
