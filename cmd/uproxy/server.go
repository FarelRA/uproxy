package main

import (
	"context"
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
	"uproxy/internal/kcp"
	"uproxy/internal/socks5"
	"uproxy/internal/tun"
	"uproxy/internal/uproxy"
)

func serverCmd() *cobra.Command {
	cfg := config.NewDefaultServerConfig()

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run uproxy server (KCP+SSH SOCKS5/TUN server)",
		RunE: func(cmd *cobra.Command, args []string) error {
			config.InitializeCommon(cfg.LogLevel, cfg.LogFormat, &cfg.SSH, true, uproxy.InitLogger)
			return runServer(cmd.Context(), &cfg)
		},
	}

	config.AddServerFlags(cmd, &cfg)
	return cmd
}

func runServer(ctx context.Context, cfg *config.ServerConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Load SSH host key
	signer, err := uproxy.LoadPrivateKey(cfg.SSH.Dir, cfg.SSH.PrivateKey)
	if err != nil {
		return err
	}

	// Create SSH server config
	sshConfig := createSSHServerConfig(signer, cfg)

	// Create resilient packet connection
	packetConn := uproxy.NewResilientPacketConn(
		cfg.ListenAddr,
		"",
		cfg.ReconnectInterval,
		cfg.UDPSockBuf,
		true, // server mode - no connectivity monitoring
	)
	defer packetConn.Close()

	// Initialize TUN manager if running as root
	tunManager, err := initializeTUNManager(cfg)
	if err != nil {
		slog.Warn("TUN mode disabled", "error", err)
	}
	if tunManager != nil {
		defer tunManager.Close()
	}

	// Create KCP listener
	listener, err := kcp.ServeConn(packetConn)
	if err != nil {
		return err
	}
	defer listener.Close()

	slog.Info("Listening on KCP", "addr", cfg.ListenAddr)

	// Track active clients for graceful shutdown
	clientTracker := newClientTracker()

	// Handle shutdown signal
	go func() {
		<-sigChan
		slog.Info("Shutting down...")
		clientTracker.closeAll()
		time.Sleep(config.DefaultShutdownGracePeriod)
		listener.Close()
		cancel()
	}()

	// Accept connections
	return acceptConnections(ctx, listener, cfg, sshConfig, tunManager, clientTracker)
}

// createSSHServerConfig creates the SSH server configuration
func createSSHServerConfig(signer ssh.Signer, cfg *config.ServerConfig) *ssh.ServerConfig {
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			slog.Info("Client attempting SSH authentication",
				"remote_addr", conn.RemoteAddr(),
				"user", conn.User(),
				"key_type", key.Type(),
				"fingerprint", ssh.FingerprintSHA256(key))

			if err := uproxy.CheckAuthorizedKeys(key, cfg.SSH.Dir, cfg.SSH.AuthorizedKeys); err != nil {
				slog.Warn("SSH authentication failed",
					"remote_addr", conn.RemoteAddr(),
					"key_type", key.Type(),
					"fingerprint", ssh.FingerprintSHA256(key),
					"error", err)
				return nil, err
			}

			slog.Info("SSH authentication successful",
				"remote_addr", conn.RemoteAddr(),
				"key_type", key.Type(),
				"fingerprint", ssh.FingerprintSHA256(key))
			return &ssh.Permissions{}, nil
		},
	}
	sshConfig.AddHostKey(signer)
	return sshConfig
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

// acceptConnections accepts and handles incoming KCP connections
func acceptConnections(ctx context.Context, listener *kcp.Listener, cfg *config.ServerConfig, sshConfig *ssh.ServerConfig, tunManager *tun.TUNManager, clientTracker *clientTracker) error {
	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Error("Accept error", "error", err)
				continue
			}
		}

		// Configure KCP session
		conn.SetStreamMode(true)
		cfg.KCP.ToKCPConfig().Apply(conn)
		conn.SetDeadLink(config.DefaultKCPDeadLink)

		// Handle connection in background
		go handleSSHConnection(ctx, conn, sshConfig, cfg, tunManager, clientTracker)
	}
}

// handleSSHConnection handles a single SSH connection
func handleSSHConnection(ctx context.Context, conn net.Conn, sshConfig *ssh.ServerConfig, cfg *config.ServerConfig, tunManager *tun.TUNManager, clientTracker *clientTracker) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		slog.Error("SSH handshake failed", "error", err)
		conn.Close()
		return
	}

	slog.Info("Client connected (SSH auth success)", "layer", "ssh", "addr", sshConn.RemoteAddr().String())

	clientTracker.add(sshConn)
	defer clientTracker.remove(sshConn)

	go ssh.DiscardRequests(reqs)

	// Create channel handler
	handler := newChannelHandler(ctx, cfg, tunManager, sshConn.RemoteAddr())

	// Handle incoming channels
	for newChan := range chans {
		if err := handler.handle(newChan); err != nil {
			slog.Warn("Channel handling failed", "type", newChan.ChannelType(), "error", err)
		}
	}
}

// channelHandler handles different SSH channel types
type channelHandler struct {
	ctx        context.Context
	cfg        *config.ServerConfig
	tunManager *tun.TUNManager
	remoteAddr net.Addr
}

func newChannelHandler(ctx context.Context, cfg *config.ServerConfig, tunManager *tun.TUNManager, remoteAddr net.Addr) *channelHandler {
	return &channelHandler{
		ctx:        ctx,
		cfg:        cfg,
		tunManager: tunManager,
		remoteAddr: remoteAddr,
	}
}

// handle dispatches channel handling based on type
func (h *channelHandler) handle(newChan ssh.NewChannel) error {
	switch newChan.ChannelType() {
	case socks5.ChannelTypeTCP:
		return h.handleTCP(newChan)
	case socks5.ChannelTypeUDP:
		return h.handleUDP(newChan)
	case tun.ChannelTypeTUN:
		return h.handleTUN(newChan)
	default:
		newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
		return nil
	}
}

func (h *channelHandler) handleTCP(newChan ssh.NewChannel) error {
	channel, requests, err := newChan.Accept()
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(requests)
	go socks5.HandleTCP(h.ctx, channel, h.remoteAddr, h.cfg.Outbound, h.cfg.ProxyDialTimeout, h.cfg.TCPBufSize)
	return nil
}

func (h *channelHandler) handleUDP(newChan ssh.NewChannel) error {
	channel, requests, err := newChan.Accept()
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(requests)
	go socks5.HandleUDP(h.ctx, channel, h.cfg.Outbound, h.cfg.ProxyDialTimeout)
	return nil
}

func (h *channelHandler) handleTUN(newChan ssh.NewChannel) error {
	if h.tunManager == nil {
		return newChan.Reject(ssh.Prohibited, "TUN mode is not enabled")
	}

	channel, requests, err := newChan.Accept()
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(requests)
	go tun.HandleTUN(channel, h.tunManager)
	return nil
}

// clientTracker tracks active SSH connections for graceful shutdown
type clientTracker struct {
	mu      sync.Mutex
	clients map[*ssh.ServerConn]struct{}
}

func newClientTracker() *clientTracker {
	return &clientTracker{
		clients: make(map[*ssh.ServerConn]struct{}),
	}
}

func (ct *clientTracker) add(conn *ssh.ServerConn) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.clients[conn] = struct{}{}
}

func (ct *clientTracker) remove(conn *ssh.ServerConn) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	delete(ct.clients, conn)
}

func (ct *clientTracker) closeAll() {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for client := range ct.clients {
		client.Close()
	}
}
