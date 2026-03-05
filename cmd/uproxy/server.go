package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/spf13/cobra"

	"uproxy/internal/config"
	"uproxy/internal/quictransport"
	"uproxy/internal/socks5"
	"uproxy/internal/tun"
	"uproxy/internal/uproxy"
)

func serverCmd() *cobra.Command {
	cfg := config.NewDefaultServerConfig()

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run uproxy server (QUIC+mTLS SOCKS5/TUN server)",
		RunE: func(cmd *cobra.Command, args []string) error {
			config.InitializeCommon(cfg.LogLevel, cfg.LogFormat, &cfg.SSH, true, uproxy.InitLogger)
			return runServer(cmd.Context(), &cfg)
		},
	}

	config.AddServerFlags(cmd, &cfg)
	return cmd
}

func runServer(ctx context.Context, cfg *config.ServerConfig) (err error) {
	// Ensure cleanup happens even on panic
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Server panic recovered", "panic", r)
			err = fmt.Errorf("server panic: %v", r)
		}
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Load SSH private key and convert to TLS certificate
	signer, err := uproxy.LoadPrivateKey(cfg.SSH.Dir, cfg.SSH.PrivateKey)
	if err != nil {
		return err
	}

	// Convert SSH key to TLS certificate (365 days validity, no hostnames for mTLS)
	tlsCert, err := uproxy.SSHSignerToTLSCertificate(signer, 365*24*time.Hour, nil)
	if err != nil {
		return fmt.Errorf("failed to convert SSH key to TLS certificate: %w", err)
	}

	// Create TLS config with client certificate verification
	tlsConfig, err := quictransport.NewServerTLSConfig(
		tlsCert,
		func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return uproxy.VerifyClientCertificate(rawCerts, cfg.SSH.Dir, cfg.SSH.AuthorizedKeys)
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}

	// Initialize TUN manager if running as root
	tunManager, err := initializeTUNManager(cfg)
	if err != nil {
		slog.Warn("TUN mode disabled", "error", err)
	}
	if tunManager != nil {
		defer tunManager.Close()
	}

	// Parse listen address
	listenAddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to parse listen address: %w", err)
	}

	// Create QUIC server with configuration from flags
	quicOpts := quictransport.QUICConfigOptions{
		MaxIdleTimeout:                 cfg.QUIC.MaxIdleTimeout,
		MaxIncomingStreams:             cfg.QUIC.MaxIncomingStreams,
		MaxIncomingUniStreams:          cfg.QUIC.MaxIncomingUniStreams,
		InitialStreamReceiveWindow:     cfg.QUIC.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         cfg.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: cfg.QUIC.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     cfg.QUIC.MaxConnectionReceiveWindow,
		KeepAlivePeriod:                cfg.QUIC.KeepAlivePeriod,
		DisablePathMTUDiscovery:        cfg.QUIC.DisablePathMTUDiscovery,
		Enable0RTT:                     cfg.QUIC.Enable0RTT,
	}
	quicConfig := quictransport.NewQUICConfig(&quicOpts)
	server := quictransport.NewServer(listenAddr, tlsConfig, quicConfig)

	if err := server.Listen(); err != nil {
		return fmt.Errorf("failed to start QUIC listener: %w", err)
	}
	defer server.Close()

	slog.Info("Listening on QUIC", "addr", cfg.ListenAddr)

	// Track active clients for graceful shutdown
	clientTracker := newClientTracker()

	// Handle shutdown signal
	go func() {
		<-sigChan
		slog.Info("Shutting down...")
		clientTracker.closeAll()
		time.Sleep(config.DefaultShutdownGracePeriod)
		server.Close()
		cancel()
	}()

	// Accept connections
	return acceptConnections(ctx, server, cfg, tunManager, clientTracker)
}

// initializeTUNManager initializes the TUN manager if conditions are met
func initializeTUNManager(cfg *config.ServerConfig) (*tun.TUNManager, error) {
	if !uproxy.IsRoot() {
		slog.Info("TUN mode disabled (not running as root). Only SOCKS5 mode available.")
		slog.Info("To enable TUN mode, run with: sudo uproxy server ...")
		return nil, nil
	}

	if cfg.TUN.IP == "" {
		slog.Info("TUN mode not configured. Only SOCKS5 mode available.")
		slog.Info("To enable TUN mode, run with: sudo uproxy server --tun-ip <ip> ...")
		return nil, nil
	}

	tunCfg := &tun.Config{
		Name:    cfg.TUN.Name,
		IP:      cfg.TUN.IP,
		Netmask: cfg.TUN.Netmask,
		IPv6:    cfg.TUN.IPv6,
		MTU:     cfg.TUN.MTU,
	}

	tunManager, err := tun.NewTUNManager(tunCfg, cfg.Outbound, cfg.TUN.AutoRoute)
	if err != nil {
		return nil, err
	}

	slog.Info("TUN manager initialized (running as root)",
		"device", tunCfg.Name,
		"ipv4", tunCfg.IP,
		"ipv6", tunCfg.IPv6,
		"auto_route", cfg.TUN.AutoRoute)

	return tunManager, nil
}

// acceptConnections accepts and handles incoming QUIC connections
func acceptConnections(ctx context.Context, server *quictransport.Server, cfg *config.ServerConfig, tunManager *tun.TUNManager, clientTracker *clientTracker) error {
	for {
		conn, err := server.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Error("Accept error", "error", err)
				continue
			}
		}

		slog.Info("Client connected (mTLS auth success)", "layer", "quic", "addr", conn.RemoteAddr().String())

		clientTracker.add(conn)

		// Handle connection in background
		go handleQUICConnection(ctx, conn, cfg, tunManager, clientTracker)
	}
}

// handleQUICConnection handles a single QUIC connection by accepting streams
func handleQUICConnection(ctx context.Context, conn *quic.Conn, cfg *config.ServerConfig, tunManager *tun.TUNManager, clientTracker *clientTracker) {
	defer clientTracker.remove(conn)
	defer conn.CloseWithError(0, "connection closed")

	remoteAddr := conn.RemoteAddr()
	localAddr := conn.LocalAddr()

	// Accept streams from this connection
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			if err != io.EOF {
				slog.Debug("Stream accept error", "remote_addr", remoteAddr, "error", err)
			}
			return
		}

		// Handle stream in background
		go handleStream(ctx, stream, cfg, tunManager, remoteAddr, localAddr)
	}
}

// handleStream reads the stream type marker and routes to the appropriate handler
func handleStream(ctx context.Context, stream *quic.Stream, cfg *config.ServerConfig, tunManager *tun.TUNManager, remoteAddr, localAddr net.Addr) {
	// Read stream type marker (first byte)
	streamType, err := quictransport.ReadStreamType(stream)
	if err != nil {
		slog.Warn("Failed to read stream type", "remote_addr", remoteAddr, "error", err)
		stream.Close()
		return
	}

	// Wrap stream as net.Conn
	streamConn := quictransport.NewStreamWrapper(stream, localAddr, remoteAddr)

	// Route based on stream type
	switch streamType {
	case quictransport.StreamTypeTCP:
		socks5.HandleTCP(ctx, streamConn, remoteAddr, cfg.Outbound, cfg.ProxyDialTimeout, cfg.TCPBufSize)
	case quictransport.StreamTypeUDP:
		socks5.HandleUDP(ctx, streamConn, cfg.Outbound, cfg.ProxyDialTimeout)
	case quictransport.StreamTypeTUN:
		if tunManager == nil {
			slog.Warn("TUN stream rejected (TUN mode not enabled)", "remote_addr", remoteAddr)
			streamConn.Close()
			return
		}
		tun.HandleTUN(streamConn, tunManager)
	default:
		slog.Warn("Unknown stream type", "remote_addr", remoteAddr, "type", streamType)
		streamConn.Close()
	}
}

// clientTracker tracks active QUIC connections for graceful shutdown
type clientTracker struct {
	mu      sync.Mutex
	clients map[*quic.Conn]struct{}
}

func newClientTracker() *clientTracker {
	return &clientTracker{
		clients: make(map[*quic.Conn]struct{}),
	}
}

func (ct *clientTracker) add(conn *quic.Conn) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.clients[conn] = struct{}{}
}

func (ct *clientTracker) remove(conn *quic.Conn) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.clients, conn)
}

func (ct *clientTracker) closeAll() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for client := range ct.clients {
		client.CloseWithError(0, "server shutdown")
	}
}
