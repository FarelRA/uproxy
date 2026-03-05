package socks5

import (
	"context"
	"fmt"
	"net"
	"time"

	"uproxy/internal/common"
	"uproxy/internal/quictransport"
	"uproxy/internal/uproxy"
)

// HandleTCP runs on the server side to handle an incoming TCP QUIC stream.
func HandleTCP(ctx context.Context, stream net.Conn, remoteAddr net.Addr, outbound string, dialTimeout time.Duration, tcpBufSize int) {
	defer stream.Close()

	targetAddr, err := ReadTargetHeader(stream)
	if err != nil {
		common.LogError("quic_tcp", "Failed to read TCP target header", "error", err)
		return
	}

	dialer, err := uproxy.CreateDialer("tcp", outbound, dialTimeout)
	if err != nil {
		common.LogError("quic_tcp", "Failed to create dialer", "iface", outbound, "error", err)
		return
	}

	targetConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		common.LogError("quic_tcp", "Failed to dial TCP target", "target", targetAddr, "error", err)
		return
	}
	defer targetConn.Close()

	uproxy.OptimizeTCPConn(targetConn)

	// Proxy bidirectionally with zero-copy pools and full telemetry
	uproxy.ProxyBidi(ctx, stream, targetConn, "socks5_server_tcp", targetAddr, tcpBufSize)
}

// DialTCP runs on the client side to establish a new TCP QUIC stream to the server.
func DialTCP(ctx context.Context, quicClient *quictransport.Client, targetAddr string) (net.Conn, error) {
	stream, err := quicClient.OpenTCPStream(ctx)
	if err != nil {
		return nil, err
	}

	if err := WriteTargetHeader(stream, targetAddr); err != nil {
		stream.Close()
		return nil, fmt.Errorf("failed to write target header: %w", err)
	}

	return stream, nil
}
