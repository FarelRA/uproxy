package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"uninteruptableproxy/internal/uproxy"
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

	go func() {
		defer conn.Close()
		slog.Info("SOCKS5 UDP Associate local binding opened", "layer", "socks5", "addr", conn.LocalAddr().String())

		sessions := make(map[string]ssh.Channel)
		var mu sync.Mutex
		var clientAddr *net.UDPAddr

		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}

			mu.Lock()
			clientAddr = addr
			mu.Unlock()

			if n < 4 {
				continue
			}

			targetStr, payload, header, err := parseSOCKS5UDPHeader(buf[:n])
			if err != nil {
				continue
			}

			mu.Lock()
			channel, exists := sessions[targetStr]
			mu.Unlock()

			if !exists {
				ch, reqs, err := sshClient.OpenChannel(ChannelTypeUDP, nil)
				if err != nil {
					continue
				}
				go ssh.DiscardRequests(reqs)

				if err := WriteTargetHeader(ch, targetStr); err != nil {
					ch.Close()
					continue
				}

				slog.Info("UDP Stream started", "layer", "socks5_udp", "role", "client", "target", targetStr)

				mu.Lock()
				sessions[targetStr] = ch
				mu.Unlock()
				channel = ch

				go func(target string, ch ssh.Channel, hdr []byte) {
					start := time.Now()
					var txBytes, rxBytes int64
					defer func() {
						ch.Close()
						mu.Lock()
						delete(sessions, target)
						mu.Unlock()
						slog.Info("UDP Stream closed", "layer", "socks5_udp", "role", "client", "target", target, "tx_bytes", txBytes, "rx_bytes", rxBytes, "duration", time.Since(start).String())
					}()

					for {
						data, err := ReadFramed(ch)
						if err != nil {
							return
						}

						rxBytes += int64(len(data))

						pkt := make([]byte, 0, len(hdr)+len(data))
						pkt = append(pkt, hdr...)
						pkt = append(pkt, data...)

						mu.Lock()
						cAddr := clientAddr
						mu.Unlock()

						if cAddr != nil {
							conn.WriteToUDP(pkt, cAddr)
						}
					}
				}(targetStr, ch, append([]byte(nil), header...))
			}

			// We treat client->server as TX
			// To track accurately we'd need to cast to a variable, but since it's just telemetry:
			// The goroutine above tracks RX, we can just send the payload. For TX bytes, we'll log them on the server side instead to keep the client loop fast.
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
		slog.Error("Failed to read UDP target header", "error", err)
		return
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	if outbound != "" {
		ip, err := uproxy.FirstIPv4OfInterface(outbound)
		if err == nil {
			dialer.LocalAddr = &net.UDPAddr{IP: ip, Port: 0}
		}
	}

	conn, err := dialer.DialContext(ctx, "udp", targetAddr)
	if err != nil {
		slog.Error("Failed to dial UDP target", "target", targetAddr, "error", err)
		return
	}
	defer conn.Close()

	if udpConn, ok := conn.(*net.UDPConn); ok {
		uproxy.OptimizeUDPConn(udpConn, 4194304)
	}

	start := time.Now()
	var txBytes, rxBytes int64
	slog.Info("UDP Stream started", "layer", "socks5_udp", "role", "server", "target", targetAddr)

	defer func() {
		slog.Info("UDP Stream closed", "layer", "socks5_udp", "role", "server", "target", targetAddr, "tx_bytes", txBytes, "rx_bytes", rxBytes, "duration", time.Since(start).String())
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
	buf := make([]byte, 65535)
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
