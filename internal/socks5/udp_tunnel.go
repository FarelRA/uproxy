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
	"uproxy/internal/framing"
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

	// Use common address parsing function
	host, newIdx, err := parseSOCKS5Address(data, atyp, idx)
	if err != nil {
		return "", nil, nil, err
	}
	idx = newIdx

	if len(data) < idx+2 {
		return "", nil, nil, io.ErrUnexpectedEOF
	}
	port := binary.BigEndian.Uint16(data[idx : idx+2])
	idx += 2

	target = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return target, data[idx:], data[:idx], nil
}

// udpSessionManager manages UDP sessions for SOCKS5 UDP ASSOCIATE requests.
// It maintains a mapping of target addresses to SSH channels, allowing multiple
// UDP destinations to be multiplexed over a single UDP socket. The manager handles
// session creation, reuse, and cleanup for efficient UDP proxying.
//
// Thread-safe: All public methods use mutex locking to ensure concurrent access safety.
type udpSessionManager struct {
	sessions   map[string]ssh.Channel // Maps target addresses to SSH channels
	mu         sync.Mutex             // Protects sessions and clientAddr
	clientAddr *net.UDPAddr           // Client's UDP address for sending responses
	sshClient  *ssh.Client            // SSH client for creating new channels
	conn       *net.UDPConn           // Local UDP socket for client communication
	wg         sync.WaitGroup         // Tracks active session goroutines
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

	m.wg.Add(1)
	go m.handleSessionResponses(targetStr, ch, header)

	return ch, nil
}

func (m *udpSessionManager) handleSessionResponses(target string, ch ssh.Channel, header []byte) {
	start := time.Now()
	var txBytes, rxBytes int64
	defer func() {
		m.wg.Done()
		ch.Close()
		m.mu.Lock()
		delete(m.sessions, target)
		m.mu.Unlock()
		common.LogInfo("socks5_udp", "UDP Stream closed", "role", "client", "target", target, "tx_bytes", txBytes, "rx_bytes", rxBytes, "duration", time.Since(start).String())
	}()

	for {
		data, err := framing.ReadFramed(ch)
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
			if _, err := m.conn.WriteToUDP(pkt, cAddr); err != nil {
				common.LogDebug("socks5_udp", "Failed to write UDP packet to client", "error", err)
			}
		}
	}
}

// udpCloser wraps the UDP connection and waits for all session goroutines to complete
type udpCloser struct {
	conn       *net.UDPConn
	sessionMgr *udpSessionManager
}

func (c *udpCloser) Close() error {
	err := c.conn.Close()
	c.sessionMgr.wg.Wait()
	return err
}

// DialUDP runs on the client side. It binds a local UDP socket and pipes SOCKS5 UDP frames into SSH channels.
func DialUDP(ctx context.Context, sshClient *ssh.Client, listenIP string) (net.Addr, io.Closer, error) {
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

		withUDPBuffer(func(buf []byte) {
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

				if err := framing.WriteFramed(channel, payload); err != nil {
					common.LogDebug("socks5_udp", "Failed to write framed data to channel", "target", targetStr, "error", err)
				}
			}
		})
	}()

	return conn.LocalAddr(), &udpCloser{conn: conn, sessionMgr: sessionMgr}, nil
}

// createDialer creates a net.Dialer configured for the specified network type with optional interface binding.
// Supports both "tcp" and "udp" network types.
func createDialer(network, outbound string, dialTimeout time.Duration) (*net.Dialer, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	if outbound != "" {
		// Try to get IP from interface (supports both IPv4 and IPv6)
		ip, err := uproxy.FirstIPOfInterface(outbound)
		if err != nil {
			return nil, err
		}

		switch network {
		case "tcp":
			dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: 0}
		case "udp":
			dialer.LocalAddr = &net.UDPAddr{IP: ip, Port: 0}
		}
	}
	return dialer, nil
}

// withUDPBuffer executes a function with a pooled UDP buffer.
func withUDPBuffer(fn func([]byte)) {
	bufPtr := getUDPBuffer()
	defer putUDPBuffer(bufPtr)
	fn(*bufPtr)
}

// forwardChannelToConn forwards data from SSH channel to UDP connection.
func forwardChannelToConn(channel ssh.Channel, conn net.Conn, txBytes *int64, timeout time.Duration) {
	for {
		data, err := framing.ReadFramed(channel)
		if err != nil {
			return
		}
		n, err := conn.Write(data)
		if err != nil {
			common.LogError("ssh_udp", "Failed to write UDP data", "error", err)
			return
		}
		*txBytes += int64(n)
		conn.SetReadDeadline(time.Now().Add(timeout))
	}
}

// forwardConnToChannel forwards data from UDP connection to SSH channel.
func forwardConnToChannel(conn net.Conn, channel ssh.Channel, rxBytes *int64, timeout time.Duration) {
	withUDPBuffer(func(buf []byte) {
		for {
			conn.SetReadDeadline(time.Now().Add(timeout))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}

			if err := framing.WriteFramed(channel, buf[:n]); err != nil {
				return
			}
			*rxBytes += int64(n)
		}
	})
}

// proxyUDPBidirectional handles bidirectional UDP forwarding between SSH channel and UDP connection.
func proxyUDPBidirectional(channel ssh.Channel, conn net.Conn, targetAddr string) (txBytes, rxBytes int64) {
	const udpTimeout = 5 * time.Minute

	// SSH -> Internet (TX)
	go forwardChannelToConn(channel, conn, &txBytes, udpTimeout)

	// Internet -> SSH (RX)
	forwardConnToChannel(conn, channel, &rxBytes, udpTimeout)
	return
}

// HandleUDP runs on the server side to handle an incoming UDP SSH channel.
func HandleUDP(ctx context.Context, channel ssh.Channel, outbound string, dialTimeout time.Duration) {
	defer channel.Close()

	targetAddr, err := ReadTargetHeader(channel)
	if err != nil {
		common.LogError("ssh_udp", "Failed to read UDP target header", "error", err)
		return
	}

	dialer, err := createDialer("udp", outbound, dialTimeout)
	if err != nil {
		common.LogError("ssh_udp", "Failed to create dialer", "iface", outbound, "error", err)
		return
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
	common.LogInfo("socks5_udp", "UDP Stream started", "role", "server", "target", targetAddr)

	txBytes, rxBytes := proxyUDPBidirectional(channel, conn, targetAddr)

	common.LogInfo("socks5_udp", "UDP Stream closed", "role", "server", "target", targetAddr, "tx_bytes", txBytes, "rx_bytes", rxBytes, "duration", time.Since(start).String())
}
