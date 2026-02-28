package socks5

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"uninteruptableproxy/internal/uproxy"
)

// HandleTCP runs on the server side to handle a incoming TCP SSH channel.
func HandleTCP(ctx context.Context, channel ssh.Channel, remoteAddr net.Addr, outbound string, dialTimeout time.Duration) {
	defer channel.Close()

	targetAddr, err := ReadTargetHeader(channel)
	if err != nil {
		slog.Error("Failed to read TCP target header", "layer", "ssh_tcp", "error", err)
		return
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	if outbound != "" {
		ip, err := uproxy.FirstIPv4OfInterface(outbound)
		if err != nil {
			slog.Error("Failed to get IP for iface", "layer", "ssh_tcp", "iface", outbound, "error", err)
			return
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: 0}
	}

	targetConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		slog.Error("Failed to dial TCP target", "layer", "ssh_tcp", "target", targetAddr, "error", err)
		return
	}
	defer targetConn.Close()

	uproxy.OptimizeTCPConn(targetConn)

	// Proxy bidirectionally with zero-copy pools and full telemetry
	uproxy.ProxyBidi(ctx, uproxy.NewChannelConn(channel, targetConn.LocalAddr(), remoteAddr), targetConn, "socks5_server_tcp", targetAddr)
}

// DialTCP runs on the client side to establish a new TCP SSH channel to the server.
func DialTCP(sshClient *ssh.Client, targetAddr string) (net.Conn, error) {
	channel, reqs, err := sshClient.OpenChannel(ChannelTypeTCP, nil)
	if err != nil {
		return nil, fmt.Errorf("open channel failed: %v", err)
	}
	go ssh.DiscardRequests(reqs)

	if err := WriteTargetHeader(channel, targetAddr); err != nil {
		channel.Close()
		return nil, fmt.Errorf("failed to write target header: %v", err)
	}

	return uproxy.NewChannelConn(channel, nil, nil), nil
}
