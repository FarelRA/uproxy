package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"uproxy/internal/config"
	"uproxy/internal/quictransport"
	"uproxy/internal/socks5"
	"uproxy/internal/tun"
	"uproxy/internal/uproxy"
	"uproxy/internal/validation"
)

func clientCmd() *cobra.Command {
	cfg := config.NewDefaultClientConfig()

	cmd := &cobra.Command{
		Use:   "client",
		Short: "Run uproxy client (SOCKS5 or TUN mode)",
		RunE: func(cmd *cobra.Command, args []string) error {
			config.InitializeCommon(cfg.LogLevel, cfg.LogFormat, &cfg.SSH, false, uproxy.InitLogger)
			return runClient(cmd.Context(), &cfg)
		},
	}

	config.AddClientFlags(cmd, &cfg)
	return cmd
}

func runClient(ctx context.Context, cfg *config.ClientConfig) (err error) {
	// Ensure cleanup happens even on panic
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Client panic recovered", "panic", r)
			err = fmt.Errorf("client panic: %v", r)
		}
	}()

	// Auto-detect mode based on privileges
	if cfg.Mode == "auto" {
		if uproxy.IsRoot() {
			cfg.Mode = "tun"
			slog.Info("Auto-selected TUN mode (running as root)")
		} else {
			cfg.Mode = "socks5"
			slog.Info("Auto-selected SOCKS5 mode (not running as root)")
		}
	}

	// Validate mode-specific requirements
	if err := validateMode(cfg); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		slog.Info("Shutting down...")
		cancel()
	}()

	// Load SSH private key
	signer, err := uproxy.LoadPrivateKey(cfg.SSH.Dir, cfg.SSH.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to load SSH key: %w", err)
	}

	// Create connection manager
	connMgr := newConnectionManager(cfg, signer)
	defer func() {
		connMgr.cleanup()
	}()

	// Start connection loop in background
	go connMgr.connectLoop(ctx)

	// Start proxy based on mode
	return startProxy(ctx, cfg, connMgr)
}

// validateMode validates mode-specific requirements
func validateMode(cfg *config.ClientConfig) error {
	return validation.ValidateClientMode(cfg)
}

// connectionManager manages the QUIC connection lifecycle
type connectionManager struct {
	cfg     *config.ClientConfig
	signer  ssh.Signer
	tlsCert tls.Certificate

	mu         sync.RWMutex
	quicClient *quictransport.Client
}

func newConnectionManager(cfg *config.ClientConfig, signer ssh.Signer) *connectionManager {
	return &connectionManager{
		cfg:    cfg,
		signer: signer,
	}
}

// getQUICClient returns the current QUIC client (thread-safe)
func (cm *connectionManager) getQUICClient() *quictransport.Client {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.quicClient
}

// connectLoop maintains connection with automatic reconnection
func (cm *connectionManager) connectLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := cm.establishConnection(ctx); err != nil {
			slog.Warn("Connection failed, retrying...", "error", err)
			cm.closeConnection()

			select {
			case <-ctx.Done():
				return
			case <-time.After(config.DefaultReconnectRetryWait):
			}
			continue
		}

		// Wait for connection to drop
		cm.waitForDisconnection(ctx)
	}
}

// establishConnection creates a new QUIC connection to the server
func (cm *connectionManager) establishConnection(ctx context.Context) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Close any existing connections
	cm.closeConnectionLocked()

	slog.Info("Connecting to server via QUIC", "addr", cm.cfg.ServerAddr)

	// Generate TLS certificate from SSH key if not already cached
	if cm.tlsCert.Certificate == nil {
		cert, err := uproxy.SSHSignerToTLSCertificate(cm.signer, 365*24*time.Hour, nil)
		if err != nil {
			return fmt.Errorf("failed to generate TLS certificate from SSH key: %w", err)
		}
		cm.tlsCert = cert
		slog.Debug("Generated TLS certificate from SSH key", "key_type", cm.signer.PublicKey().Type())
	}

	// Create TLS config with client certificate and server verification
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cm.tlsCert},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return uproxy.VerifyServerCertificate(rawCerts, cm.cfg.ServerAddr, cm.cfg.SSH.Dir, cm.cfg.SSH.KnownHosts)
		},
		NextProtos: []string{"uproxy-quic"},
	}

	// Create QUIC client with configuration from flags
	quicOpts := quictransport.QUICConfigOptions{
		HandshakeIdleTimeout:           cm.cfg.QUIC.HandshakeIdleTimeout,
		MaxIdleTimeout:                 cm.cfg.QUIC.MaxIdleTimeout,
		MaxIncomingStreams:             cm.cfg.QUIC.MaxIncomingStreams,
		MaxIncomingUniStreams:          cm.cfg.QUIC.MaxIncomingUniStreams,
		InitialStreamReceiveWindow:     cm.cfg.QUIC.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         cm.cfg.QUIC.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: cm.cfg.QUIC.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     cm.cfg.QUIC.MaxConnectionReceiveWindow,
		KeepAlivePeriod:                cm.cfg.QUIC.KeepAlivePeriod,
		InitialPacketSize:              cm.cfg.QUIC.InitialPacketSize,
		DisablePathMTUDiscovery:        cm.cfg.QUIC.DisablePathMTUDiscovery,
		Enable0RTT:                     cm.cfg.QUIC.Enable0RTT,
		EnableDatagrams:                cm.cfg.QUIC.EnableDatagrams,
	}
	quicConfig := quictransport.NewQUICConfig(&quicOpts)

	// Resolve server address
	serverAddr, err := net.ResolveUDPAddr("udp", cm.cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve server address: %w", err)
	}

	client := quictransport.NewClient(serverAddr, tlsConfig, quicConfig)
	cm.quicClient = client

	// Connect to server
	slog.Info("Attempting QUIC connection",
		"server", cm.cfg.ServerAddr,
		"key_type", cm.signer.PublicKey().Type(),
		"fingerprint", ssh.FingerprintSHA256(cm.signer.PublicKey()))

	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("QUIC connection failed: %w", err)
	}

	slog.Info("Connected to server via QUIC+mTLS", "addr", cm.cfg.ServerAddr)
	return nil
}

// waitForDisconnection blocks until the QUIC connection is lost
func (cm *connectionManager) waitForDisconnection(ctx context.Context) {
	cm.mu.RLock()
	client := cm.quicClient
	cm.mu.RUnlock()

	if client == nil {
		return
	}

	if err := client.WaitForDisconnection(ctx); err != nil {
		if err == ctx.Err() {
			cm.closeConnection()
		}
	} else {
		slog.Info("QUIC connection died. Reconnecting...")
	}
}

// closeConnection closes the current connection (thread-safe)
func (cm *connectionManager) closeConnection() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.closeConnectionLocked()
}

// closeConnectionLocked closes the current connection (must hold lock)
func (cm *connectionManager) closeConnectionLocked() {
	if cm.quicClient != nil {
		cm.quicClient.Close()
		cm.quicClient = nil
	}
}

// cleanup closes all connections and cleans up resources
func (cm *connectionManager) cleanup() {
	slog.Info("Explicitly disconnecting from server...")
	cm.closeConnection()

	// Allow time for graceful shutdown
	time.Sleep(config.DefaultShutdownGracePeriod)
}

// startProxy starts the appropriate proxy mode
func startProxy(ctx context.Context, cfg *config.ClientConfig, connMgr *connectionManager) error {
	slog.Info("Starting proxy", "mode", cfg.Mode, "listenAddr", cfg.ListenAddr)

	switch cfg.Mode {
	case "socks5":
		return startSOCKS5Proxy(ctx, cfg, connMgr)
	case "tun":
		return startTUNTunnel(ctx, cfg, connMgr)
	default:
		return fmt.Errorf("invalid mode: %s", cfg.Mode)
	}
}

// startSOCKS5Proxy starts the SOCKS5 proxy server
func startSOCKS5Proxy(ctx context.Context, cfg *config.ClientConfig, connMgr *connectionManager) error {
	return startSOCKS5Server(ctx, cfg.ListenAddr, cfg.TCPBufSize, connMgr.getQUICClient, "socks5")
}

// startSOCKS5Server is a helper that starts a SOCKS5 server with the given configuration
func startSOCKS5Server(ctx context.Context, listenAddr string, tcpBufSize int, getClient func() *quictransport.Client, layer string) error {
	slog.Info("SOCKS5 TCP/UDP proxy listening", "layer", layer, "addr", listenAddr)
	return socks5.ServeSOCKS5(ctx, listenAddr, tcpBufSize,
		func(ctx context.Context, addr string) (net.Conn, error) {
			client := getClient()
			if client == nil {
				return nil, fmt.Errorf("quic client not connected")
			}
			stream, err := client.OpenTCPStream(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to open TCP stream: %w", err)
			}
			return stream, nil
		},
		func(ctx context.Context) (net.Addr, io.Closer, error) {
			client := getClient()
			if client == nil {
				return nil, nil, fmt.Errorf("quic client not connected")
			}
			stream, err := client.OpenUDPStream(ctx)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to open UDP stream: %w", err)
			}
			localAddr := client.LocalAddr()
			if localAddr == nil {
				localAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
			}
			return localAddr, stream, nil
		})
}

// shouldFallbackToSOCKS5 checks if the error indicates the server doesn't support TUN mode
func shouldFallbackToSOCKS5(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, tun.ErrTUNNotSupported)
}

// waitForQUICClient waits for the QUIC client to be connected before starting TUN
func waitForQUICClient(ctx context.Context, connMgr *connectionManager) (*quictransport.Client, error) {
	for {
		client := connMgr.getQUICClient()
		if client != nil && client.IsConnected() {
			return client, nil
		}

		slog.Warn("Waiting for QUIC connection before starting TUN...")
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(config.SSHConnectionWaitInterval):
		}
	}
}

func handleTUNError(err error, tunFailed bool, fallbackCh chan<- struct{}) (shouldReturn bool, newTunFailed bool) {
	if err == nil {
		return false, tunFailed
	}

	// Check if server doesn't support TUN mode
	if shouldFallbackToSOCKS5(err) {
		if !tunFailed {
			slog.Warn("Server does not support TUN mode, falling back to SOCKS5...")
			tunFailed = true
			select {
			case fallbackCh <- struct{}{}:
			default:
			}
		}
		return true, tunFailed
	}

	slog.Error("TUN tunnel stopped", "error", err)
	return false, tunFailed
}

func shouldRestartTUN(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	default:
		slog.Info("Restarting TUN tunnel...", "delay", config.DefaultReconnectRetryWait)
		time.Sleep(config.DefaultReconnectRetryWait)
		return true
	}
}

func runTUNLoop(ctx context.Context, connMgr *connectionManager, tunCfg *tun.Config, routes string, autoRoute bool, serverAddr string, fallbackCh chan<- struct{}) {
	tunFailed := false
	for {
		client, err := waitForQUICClient(ctx, connMgr)
		if err != nil {
			return
		}
		err = tun.ServeTUN(ctx, client, tunCfg, routes, autoRoute, serverAddr)

		shouldReturn, newTunFailed := handleTUNError(err, tunFailed, fallbackCh)
		tunFailed = newTunFailed
		if shouldReturn {
			return
		}

		if !shouldRestartTUN(ctx) {
			return
		}
	}
}

func startSOCKS5Fallback(ctx context.Context, listenAddr string, connMgr *connectionManager) {
	go func() {
		if err := startSOCKS5Server(ctx, listenAddr, connMgr.cfg.TCPBufSize, connMgr.getQUICClient, "fallback"); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("SOCKS5 proxy server stopped", "layer", "fallback", "error", err)
		}
	}()
}

func monitorTUNFallback(ctx context.Context, fallbackCh <-chan struct{}, listenAddr string, connMgr *connectionManager) {
	select {
	case <-fallbackCh:
		startSOCKS5Fallback(ctx, listenAddr, connMgr)
	case <-ctx.Done():
		return
	}
}

func startTUNTunnel(ctx context.Context, cfg *config.ClientConfig, connMgr *connectionManager) error {
	tunCfg := &tun.Config{
		Name: cfg.TUN.Name,
		MTU:  cfg.TUN.MTU,
	}

	fallbackToSOCKS5 := make(chan struct{}, 1)

	// Start TUN tunnel loop
	go runTUNLoop(ctx, connMgr, tunCfg, cfg.TUN.Routes, cfg.TUN.AutoRoute, cfg.ServerAddr, fallbackToSOCKS5)
	slog.Info("TUN tunnel starting", "device", tunCfg.Name)

	// Monitor for fallback signal
	go monitorTUNFallback(ctx, fallbackToSOCKS5, cfg.ListenAddr, connMgr)

	<-ctx.Done()
	return nil
}
