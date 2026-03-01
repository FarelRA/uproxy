package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"
	"uproxy/internal/config"
	"uproxy/internal/uproxy"
)

// ServeSOCKS5 binds the local listening port and dispatches SOCKS5 requests
func ServeSOCKS5(ctx context.Context, listenAddr string, dialTCP func(addr string) (net.Conn, error), dialUDP func() (net.Addr, io.Closer, error)) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go handleSOCKS5Client(conn, dialTCP, dialUDP)
	}
}

func handleSOCKS5Client(conn net.Conn, dialTCP func(string) (net.Conn, error), dialUDP func() (net.Addr, io.Closer, error)) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().String()

	if err := performSOCKS5Handshake(conn); err != nil {
		return
	}

	cmd, targetAddr, err := parseSOCKS5Request(conn)
	if err != nil {
		return
	}

	switch cmd {
	case 1: // CONNECT (TCP)
		handleConnectCommand(conn, targetAddr, clientAddr, dialTCP)
	case 3: // UDP ASSOCIATE
		handleUDPAssociate(conn, clientAddr, dialUDP)
	default: // Command not supported
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func performSOCKS5Handshake(conn net.Conn) error {
	var buf [2]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return io.ErrUnexpectedEOF
	}

	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// We support 'No Auth' (0x00)
	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

func parseSOCKS5Request(conn net.Conn) (cmd byte, targetAddr string, err error) {
	var req [4]byte
	if _, err = io.ReadFull(conn, req[:]); err != nil {
		return
	}
	if req[0] != 0x05 {
		err = io.ErrUnexpectedEOF
		return
	}

	cmd = req[1]
	atyp := req[3]

	var host string
	switch atyp {
	case 1: // IPv4
		var ip [4]byte
		if _, err = io.ReadFull(conn, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 3: // Domain name
		var l [1]byte
		if _, err = io.ReadFull(conn, l[:]); err != nil {
			return
		}
		domain := make([]byte, l[0])
		if _, err = io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case 4: // IPv6
		var ip [16]byte
		if _, err = io.ReadFull(conn, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	default:
		err = io.ErrUnexpectedEOF
		return
	}

	var portBuf [2]byte
	if _, err = io.ReadFull(conn, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	targetAddr = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

func handleConnectCommand(conn net.Conn, targetAddr, clientAddr string, dialTCP func(string) (net.Conn, error)) {
	slog.Debug("SOCKS5 TCP request", "layer", "socks5", "client", clientAddr, "target", targetAddr)
	remote, err := dialTCP(targetAddr)
	if err != nil {
		slog.Error("TCP Connect failed", "layer", "socks5", "client", clientAddr, "target", targetAddr, "error", err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// Success reply
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Delegate to ProxyBidi for telemetry
	uproxy.ProxyBidi(context.Background(), conn, remote, "socks5_client_tcp", targetAddr, config.DefaultTCPBufSize)
}

func handleUDPAssociate(conn net.Conn, clientAddr string, dialUDP func() (net.Addr, io.Closer, error)) {
	slog.Debug("SOCKS5 UDP Associate request", "layer", "socks5", "client", clientAddr)
	udpAddr, udpCloser, err := dialUDP()
	if err != nil {
		slog.Error("UDP Associate failed", "layer", "socks5", "client", clientAddr, "error", err)
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpCloser.Close()

	udpIP := udpAddr.(*net.UDPAddr).IP
	udpPort := uint16(udpAddr.(*net.UDPAddr).Port)

	var rep []byte
	if ipv4 := udpIP.To4(); ipv4 != nil {
		// IPv4 address
		rep = []byte{0x05, 0x00, 0x00, 0x01}
		rep = append(rep, ipv4...)
	} else {
		// IPv6 address
		rep = []byte{0x05, 0x00, 0x00, 0x04}
		rep = append(rep, udpIP.To16()...)
	}
	rep = append(rep, byte(udpPort>>8), byte(udpPort))
	if _, err := conn.Write(rep); err != nil {
		return
	}

	// SOCKS5 spec: When the TCP connection closes, the UDP association dies.
	io.Copy(io.Discard, conn)
}
