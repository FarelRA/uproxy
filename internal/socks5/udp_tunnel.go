package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"uproxy/internal/common"
	"uproxy/internal/uproxy"
)

// parseSOCKS5UDPHeader parses the standard SOCKS5 UDP request header
func parseSOCKS5UDPHeader(data []byte) (target string, payload []byte, header []byte, err error) {
	if len(data) < 10 {
		return "", nil, nil, io.ErrUnexpectedEOF
	}
	if data[2] != 0 {
		return "", nil, nil, fmt.Errorf("fragmentation not supported")
	}
	atyp := data[3]
	idx := 4
	var host string

	switch atyp {
	case 1:
		if len(data) < idx+4+2 {
			return "", nil, nil, io.ErrUnexpectedEOF
		}
		host = net.IP(data[idx : idx+4]).String()
		idx += 4
	case 3:
		l := int(data[idx])
		idx++
		if len(data) < idx+l+2 {
			return "", nil, nil, io.ErrUnexpectedEOF
		}
		host = string(data[idx : idx+l])
		idx += l
	case 4:
		if len(data) < idx+16+2 {
			return "", nil, nil, io.ErrUnexpectedEOF
		}
		host = net.IP(data[idx : idx+16]).String()
		idx += 16
	default:
		return "", nil, nil, net.InvalidAddrError("invalid atyp")
	}

	port := binary.BigEndian.Uint16(data[idx : idx+2])
	idx += 2

	target = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return target, data[idx:], data[:idx], nil
}

type udpSessionManager struct {
	sessions   map[string]ssh.Channel
	mu         sync.Mutex
	clientAddr *net.UDPAddr
	sshClient  *ssh.Client
	conn       *net.UDPConn
}

func newUDPSessionManager(sshClient *ssh.Client, conn *net.UDPConn) *udpSessionManager {
	return &udpSessionManager{
		sessions:  make(map[string]ssh.Channel),
		sshClient: sshClient,
		conn:      conn,
	}
}

func (m *udpSessionManager) setClientAddr(addr *net.UDPAddr) {
	m.mu.Lock()
	m.clientAddr = addr
	m.mu.Unlock()
}

func (m *udpSessionManager) getOrCreateSession(targetStr string, header []byte) (ssh.Channel, error) {
	m.mu.Lock()
	channel, exists := m.sessions[targetStr]
	m.mu.Unlock()

	if exists {
		return channel, nil
	}

	ch, reqs, err := m.sshClient.OpenChannel(ChannelTypeUDP, nil)
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(reqs)

	if err := WriteTargetHeader(ch, targetStr); err != nil {
		ch.Close()
		return nil, err
	}

	common.LogInfo("socks5_udp", "UDP Stream started", "role", "client", "target", targetStr)

	m.mu.Lock()
	m.sessions[targetStr] = ch
	m.mu.Unlock()

	go m.handleSessionResponses(targetStr, ch, header)

	return ch, nil
}

func (m *udpSessionManager) handleSessionResponses(target string, ch ssh.Channel, header []byte) {
	start := time.Now()
	var txBytes, rxBytes int64
	defer func() {
		ch.Close()
		m.mu.Lock()
		delete(m.sessions, target)
		m.mu.Unlock()
		common.LogInfo("socks5_udp", "UDP Stream closed", "role", "client", "target", target, "tx_bytes", txBytes, "rx_bytes", rxBytes, "duration", time.Since(start).String())
	}()

	for {
		data, err := ReadFramed(ch)
		if err != nil {
			return
		}

		rxBytes += int64(len(data))

		pkt := make([]byte, 0, len(header)+len(data))
		pkt = append(pkt, header...)
		pkt = append(pkt, data...)

		m.mu.Lock()
		cAddr := m.clientAddr
		m.mu.Unlock()

		if cAddr != nil {
			m.conn.WriteToUDP(pkt, cAddr)
		}
	}
}

// DialUDP runs on the client side. It binds a local UDP socket and pipes SOCKS5 UDP frames into SSH channels.
func DialUDP(sshClient *ssh.Client, listenIP string) (net.Addr, io.Closer, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(listenIP, "0"))
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, nil, err
	}

	sessionMgr := newUDPSessionManager(sshClient, conn)

	go func() {
		defer conn.Close()
		common.LogInfo("socks5", "SOCKS5 UDP Associate local binding opened", "addr", conn.LocalAddr().String())

		bufPtr := getUDPBuffer()
		defer putUDPBuffer(bufPtr)
		buf := *bufPtr

		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			sessionMgr.setClientAddr(addr)

			if n < 4 {
				continue
			}

			targetStr, payload, header, err := parseSOCKS5UDPHeader(buf[:n])
			if err != nil {
				continue
			}

			channel, err := sessionMgr.getOrCreateSession(targetStr, header)
			if err != nil {
				continue
			}

			WriteFramed(channel, payload)
		}
	}()

	return conn.LocalAddr(), conn, nil
}

// HandleUDP runs on the server side to handle an incoming UDP SSH channel.
func HandleUDP(ctx context.Context, channel ssh.Channel, outbound string, dialTimeout time.Duration) {
	defer channel.Close()

	targetAddr, err := ReadTargetHeader(channel)
	if err != nil {
		common.LogError("ssh_udp", "Failed to read UDP target header", "error", err)
		return
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	if outbound != "" {
		// Try to get IP from interface (supports both IPv4 and IPv6)
		ip, err := uproxy.FirstIPOfInterface(outbound)
		if err == nil {
			dialer.LocalAddr = &net.UDPAddr{IP: ip, Port: 0}
		}
	}

	conn, err := dialer.DialContext(ctx, "udp", targetAddr)
	if err != nil {
		common.LogError("ssh_udp", "Failed to dial UDP target", "target", targetAddr, "error", err)
		return
	}
	defer conn.Close()

	if udpConn, ok := conn.(*net.UDPConn); ok {
		uproxy.OptimizeUDPConn(udpConn, 4194304)
	}

	start := time.Now()
	var txBytes, rxBytes int64
	common.LogInfo("socks5_udp", "UDP Stream started", "role", "server", "target", targetAddr)
	defer func() {
		common.LogInfo("socks5_udp", "UDP Stream closed", "role", "server", "target", targetAddr, "tx_bytes", txBytes, "rx_bytes", rxBytes, "duration", time.Since(start).String())
	}()

	// SSH -> Internet (TX)
	go func() {
		for {
			data, err := ReadFramed(channel)
			if err != nil {
				return
			}
			n, _ := conn.Write(data)
			txBytes += int64(n)
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		}
	}()

	// Internet -> SSH (RX)
	bufPtr := getUDPBuffer()
	defer putUDPBuffer(bufPtr)
	buf := *bufPtr
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		if err := WriteFramed(channel, buf[:n]); err != nil {
			return
		}
		rxBytes += int64(n)
	}
}
