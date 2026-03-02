package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"

	"uproxy/internal/common"
	"uproxy/internal/config"
	"uproxy/internal/uproxy"
)

// SOCKS5 error codes
const (
	replySuccess             = 0x00
	replyGeneralFailure      = 0x05
	replyCommandNotSupported = 0x07
)

// maxConcurrentConnections limits the number of concurrent SOCKS5 connections
const maxConcurrentConnections = 1000

// writeSOCKS5Error writes a SOCKS5 error response to the connection
func writeSOCKS5Error(conn net.Conn, errorCode byte) error {
	response := []byte{0x05, errorCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(response); err != nil {
		common.LogDebug("socks5", "Failed to send error response", "error", err, "errorCode", errorCode)
		return err
	}
	return nil
}

// writeSOCKS5Success writes a SOCKS5 success response to the connection
func writeSOCKS5Success(conn net.Conn, bindAddr string) error {
	response := []byte{0x05, replySuccess, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(response); err != nil {
		common.LogDebug("socks5", "Failed to send success response", "error", err)
		return err
	}
	return nil
}

// ServeSOCKS5 binds the local listening port and dispatches SOCKS5 requests
func ServeSOCKS5(ctx context.Context, listenAddr string, dialTCP func(context.Context, string) (net.Conn, error), dialUDP func(context.Context) (net.Addr, io.Closer, error)) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}

	// Use sync.Once to prevent double close
	var closeOnce sync.Once
	closeListener := func() {
		listener.Close()
	}
	defer closeOnce.Do(closeListener)

	// Track active connection handlers for graceful shutdown
	var wg sync.WaitGroup
	defer wg.Wait()

	// Connection limiter to prevent resource exhaustion
	semaphore := make(chan struct{}, maxConcurrentConnections)

	go func() {
		<-ctx.Done()
		closeOnce.Do(closeListener)
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

		// Try to acquire semaphore slot
		select {
		case semaphore <- struct{}{}:
			wg.Add(1)
			go func(c net.Conn) {
				defer func() { <-semaphore }()
				handleSOCKS5Client(ctx, c, dialTCP, dialUDP, &wg)
			}(conn)
		default:
			// Connection limit reached, reject connection
			common.LogDebug("socks5", "Connection limit reached, rejecting connection", "client", conn.RemoteAddr().String())
			conn.Close()
		}
	}
}

func handleSOCKS5Client(ctx context.Context, conn net.Conn, dialTCP func(context.Context, string) (net.Conn, error), dialUDP func(context.Context) (net.Addr, io.Closer, error), wg *sync.WaitGroup) {
	defer wg.Done()
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
	case config.SOCKS5CommandConnect: // CONNECT (TCP)
		handleConnectCommand(ctx, conn, targetAddr, clientAddr, dialTCP)
	case config.SOCKS5CommandUDPAssociate: // UDP ASSOCIATE
		handleUDPAssociate(ctx, conn, clientAddr, dialUDP)
	default: // Command not supported
		_ = writeSOCKS5Error(conn, replyCommandNotSupported)
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

	host, err := readSOCKS5Host(conn, atyp)
	if err != nil {
		return
	}

	port, err := readSOCKS5Port(conn)
	if err != nil {
		return
	}

	targetAddr = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

func readSOCKS5Host(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 1: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	case 3: // Domain name
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", err
		}
		domain := make([]byte, l[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		return string(domain), nil
	case 4: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", err
		}
		return net.IP(ip[:]).String(), nil
	default:
		return "", io.ErrUnexpectedEOF
	}
}

func readSOCKS5Port(conn net.Conn) (uint16, error) {
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(portBuf[:]), nil
}

func handleConnectCommand(ctx context.Context, conn net.Conn, targetAddr, clientAddr string, dialTCP func(context.Context, string) (net.Conn, error)) {
	common.LogDebug("socks5", "SOCKS5 TCP request", "client", clientAddr, "target", targetAddr)
	remote, err := dialTCP(ctx, targetAddr)
	if err != nil {
		common.LogError("socks5", "TCP Connect failed", "client", clientAddr, "target", targetAddr, "error", err)
		_ = writeSOCKS5Error(conn, replyGeneralFailure)
		return
	}
	defer remote.Close()

	// Success reply
	_ = writeSOCKS5Success(conn, targetAddr)

	// Delegate to ProxyBidi for telemetry
	uproxy.ProxyBidi(ctx, conn, remote, "socks5_client_tcp", targetAddr, config.DefaultTCPBufSize)
}

func handleUDPAssociate(ctx context.Context, conn net.Conn, clientAddr string, dialUDP func(context.Context) (net.Addr, io.Closer, error)) {
	common.LogDebug("socks5", "SOCKS5 UDP Associate request", "client", clientAddr)
	udpAddr, udpCloser, err := dialUDP(ctx)
	if err != nil {
		common.LogError("socks5", "UDP Associate failed", "client", clientAddr, "error", err)
		_ = writeSOCKS5Error(conn, replyGeneralFailure)
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
