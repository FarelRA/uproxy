package socks5

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"uproxy/internal/common"
	"uproxy/internal/uproxy"
)

// HandleTCP runs on the server side to handle an incoming TCP SSH channel.
func HandleTCP(ctx context.Context, channel ssh.Channel, remoteAddr net.Addr, outbound string, dialTimeout time.Duration, tcpBufSize int) {
	defer channel.Close()

	targetAddr, err := ReadTargetHeader(channel)
	if err != nil {
		common.LogError("ssh_tcp", "Failed to read TCP target header", "error", err)
		return
	}

	dialer, err := uproxy.CreateDialer("tcp", outbound, dialTimeout)
	if err != nil {
		common.LogError("ssh_tcp", "Failed to create dialer", "iface", outbound, "error", err)
		return
	}

	targetConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		common.LogError("ssh_tcp", "Failed to dial TCP target", "target", targetAddr, "error", err)
		return
	}
	defer targetConn.Close()

	uproxy.OptimizeTCPConn(targetConn)

	// Proxy bidirectionally with zero-copy pools and full telemetry
	uproxy.ProxyBidi(ctx, uproxy.NewChannelConn(channel, targetConn.LocalAddr(), remoteAddr), targetConn, "socks5_server_tcp", targetAddr, tcpBufSize)
}

// DialTCP runs on the client side to establish a new TCP SSH channel to the server.
func DialTCP(ctx context.Context, sshClient *ssh.Client, targetAddr string) (net.Conn, error) {
	channel, err := uproxy.OpenSSHChannel(sshClient, ChannelTypeTCP)
	if err != nil {
		return nil, err
	}

	if err := WriteTargetHeader(channel, targetAddr); err != nil {
		channel.Close()
		return nil, fmt.Errorf("failed to write target header: %w", err)
	}

	return uproxy.NewChannelConn(channel, nil, nil), nil
}
