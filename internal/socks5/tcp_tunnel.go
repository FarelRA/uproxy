package socks5

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"uproxy/internal/common"
	"uproxy/internal/config"
	"uproxy/internal/uproxy"
)

// HandleTCP runs on the server side to handle a incoming TCP SSH channel.
func HandleTCP(ctx context.Context, channel ssh.Channel, remoteAddr net.Addr, outbound string, dialTimeout time.Duration) {
	defer channel.Close()

	targetAddr, err := ReadTargetHeader(channel)
	if err != nil {
		common.LogError("ssh_tcp", "Failed to read TCP target header", "error", err)
		return
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	if outbound != "" {
		// Try to get IP from interface (supports both IPv4 and IPv6)
		ip, err := uproxy.FirstIPOfInterface(outbound)
		if err != nil {
			common.LogError("ssh_tcp", "Failed to get IP for iface", "iface", outbound, "error", err)
			return
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: 0}
	}

	targetConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		common.LogError("ssh_tcp", "Failed to dial TCP target", "target", targetAddr, "error", err)
		return
	}
	defer targetConn.Close()

	uproxy.OptimizeTCPConn(targetConn)

	// Proxy bidirectionally with zero-copy pools and full telemetry
	uproxy.ProxyBidi(ctx, uproxy.NewChannelConn(channel, targetConn.LocalAddr(), remoteAddr), targetConn, "socks5_server_tcp", targetAddr, config.DefaultTCPBufSize)
}

// DialTCP runs on the client side to establish a new TCP SSH channel to the server.
func DialTCP(ctx context.Context, sshClient *ssh.Client, targetAddr string) (net.Conn, error) {
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
