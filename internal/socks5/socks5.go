package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"
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

	// 1. Version identifier/method selection message
	var buf [2]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil || buf[0] != 0x05 {
		return
	}
	methods := make([]byte, buf[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// We support 'No Auth' (0x00)
	conn.Write([]byte{0x05, 0x00})

	// 2. Request message
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil || req[0] != 0x05 {
		return
	}
	cmd := req[1]
	atyp := req[3]

	var host string
	switch atyp {
	case 1: // IPv4
		var ip [4]byte
		io.ReadFull(conn, ip[:])
		host = net.IP(ip[:]).String()
	case 3: // Domain name
		var l [1]byte
		io.ReadFull(conn, l[:])
		domain := make([]byte, l[0])
		io.ReadFull(conn, domain)
		host = string(domain)
	case 4: // IPv6
		var ip [16]byte
		io.ReadFull(conn, ip[:])
		host = net.IP(ip[:]).String()
	default:
		return
	}

	var portBuf [2]byte
	io.ReadFull(conn, portBuf[:])
	port := binary.BigEndian.Uint16(portBuf[:])
	targetAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	// 3. Dispatch based on command
	switch cmd {
	case 1: // CONNECT (TCP)
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
		uproxy.ProxyBidi(context.Background(), conn, remote, "socks5_client_tcp", targetAddr)

	case 3: // UDP ASSOCIATE
		slog.Debug("SOCKS5 UDP Associate request", "layer", "socks5", "client", clientAddr)
		udpAddr, udpCloser, err := dialUDP()
		if err != nil {
			slog.Error("UDP Associate failed", "layer", "socks5", "client", clientAddr, "error", err)
			conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer udpCloser.Close()

		udpIP := udpAddr.(*net.UDPAddr).IP.To4()
		if udpIP == nil {
			udpIP = []byte{0, 0, 0, 0}
		}
		udpPort := uint16(udpAddr.(*net.UDPAddr).Port)

		rep := []byte{0x05, 0x00, 0x00, 0x01}
		rep = append(rep, udpIP...)
		rep = append(rep, byte(udpPort>>8), byte(udpPort))
		conn.Write(rep)

		// SOCKS5 spec: When the TCP connection closes, the UDP association dies.
		io.Copy(io.Discard, conn)

	default: // Command not supported
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}
