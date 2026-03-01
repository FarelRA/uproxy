package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"uproxy/internal/config"
	"uproxy/internal/kcp"
	"uproxy/internal/network"
	"uproxy/internal/socks5"
	"uproxy/internal/tun"
	"uproxy/internal/uproxy"
)

func clientCmd() *cobra.Command {
	cfg := config.NewDefaultClientConfig()

	cmd := &cobra.Command{
		Use:   "client",
		Short: "Run uproxy client (SOCKS5 or TUN mode)",
		RunE: func(cmd *cobra.Command, args []string) error {
			uproxy.InitLogger(cfg.LogLevel, cfg.LogFormat)
			config.SetupSSHPaths(&cfg.SSH, false)

			return runClient(cmd.Context(), &cfg)
		},
	}

	config.AddClientFlags(cmd, &cfg)
	return cmd
}

func runClient(ctx context.Context, cfg *config.ClientConfig) error {
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
	defer connMgr.cleanup()

	// Start connection loop in background
	go connMgr.connectLoop(ctx)

	// Start proxy based on mode
	return startProxy(ctx, cfg, connMgr)
}

// validateMode validates mode-specific requirements
func validateMode(cfg *config.ClientConfig) error {
	switch cfg.Mode {
	case "socks5":
		if cfg.ListenAddr == "" {
			return fmt.Errorf("--listen is required for socks5 mode")
		}
	case "tun":
		if !uproxy.IsRoot() {
			return fmt.Errorf("TUN mode requires root privileges. Run with sudo or use --mode socks5")
		}
	case "auto":
		// Will be resolved in runClient
	default:
		return fmt.Errorf("invalid mode: %s (must be 'auto', 'socks5', or 'tun')", cfg.Mode)
	}
	return nil
}

// connectionManager manages the SSH connection lifecycle
type connectionManager struct {
	cfg    *config.ClientConfig
	signer ssh.Signer

	mu           sync.RWMutex
	sshClient    *ssh.Client
	kcpConn      *kcp.UDPSession
	packetConn   *uproxy.ResilientPacketConn
	routeManager *tun.RouteManager
	diagnostics  *network.Diagnostics
}

func newConnectionManager(cfg *config.ClientConfig, signer ssh.Signer) *connectionManager {
	return &connectionManager{
		cfg:    cfg,
		signer: signer,
	}
}

// getSSHClient returns the current SSH client (thread-safe)
func (cm *connectionManager) getSSHClient() *ssh.Client {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.sshClient
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

// establishConnection creates a new connection to the server
func (cm *connectionManager) establishConnection(ctx context.Context) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Close any existing connections
	cm.closeConnectionLocked()

	slog.Info("Dialing server", "addr", cm.cfg.ServerAddr)

	// Create resilient packet connection
	packetConn := uproxy.NewResilientPacketConn(
		"",
		"",
		cm.cfg.ReconnectInterval,
		cm.cfg.UDPSockBuf,
		false, // client mode - enable connectivity monitoring
	)
	cm.packetConn = packetConn

	// Setup network diagnostics and failure handler
	cm.diagnostics = network.NewDiagnostics(cm.cfg.ServerAddr, slog.Default())
	packetConn.SetFailureHandler(cm.cfg.ServerAddr, cm.handleConnectivityFailure)

	// Create KCP connection
	kcpConn, err := kcp.NewConn(cm.cfg.ServerAddr, packetConn)
	if err != nil {
		packetConn.Close()
		return fmt.Errorf("KCP dial failed: %w", err)
	}
	cm.kcpConn = kcpConn

	// Configure KCP
	kcpConn.SetStreamMode(true)
	cm.cfg.KCP.ToKCPConfig().Apply(kcpConn)
	kcpConn.SetDeadLink(config.DefaultKCPDeadLink) // Disabled - connectivity monitor handles timeouts

	// Create SSH client config
	sshConfig := &ssh.ClientConfig{
		User: "proxy",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(cm.signer),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return uproxy.VerifyKnownHost(hostname, remote, key, cm.cfg.SSH.Dir, cm.cfg.SSH.KnownHosts)
		},
		Timeout: cm.cfg.SSHTimeout,
	}

	slog.Info("Attempting SSH authentication",
		"server", cm.cfg.ServerAddr,
		"user", "proxy",
		"key_type", cm.signer.PublicKey().Type(),
		"fingerprint", ssh.FingerprintSHA256(cm.signer.PublicKey()))

	// Establish SSH connection
	sshClientConn, sshChans, sshReqs, err := ssh.NewClientConn(kcpConn, cm.cfg.ServerAddr, sshConfig)
	if err != nil {
		kcpConn.Close()
		packetConn.Close()
		return fmt.Errorf("SSH handshake failed: %w", err)
	}

	cm.sshClient = ssh.NewClient(sshClientConn, sshChans, sshReqs)
	slog.Info("Connected to server via KCP+SSH (Resilient)", "layer", "ssh")

	return nil
}

// waitForDisconnection blocks until the connection is lost
func (cm *connectionManager) waitForDisconnection(ctx context.Context) {
	cm.mu.RLock()
	client := cm.sshClient
	cm.mu.RUnlock()

	if client == nil {
		return
	}

	done := make(chan struct{})
	go func() {
		client.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		cm.closeConnection()
	case <-done:
		slog.Info("SSH connection died. Reconnecting...")
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
	if cm.sshClient != nil {
		cm.sshClient.Close()
		cm.sshClient = nil
	}
	if cm.kcpConn != nil {
		cm.kcpConn.Close()
		cm.kcpConn = nil
	}
	if cm.packetConn != nil {
		cm.packetConn.Close()
		cm.packetConn = nil
	}
}

// handleConnectivityFailure is called when connectivity issues are detected
func (cm *connectionManager) handleConnectivityFailure(result network.DiagnosticResult) bool {
	switch result.FailureType {
	case network.FailureRouteChanged:
		// Route changed - reset routes if we have a route manager
		if cm.routeManager != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := cm.routeManager.ResetRoutes(ctx); err != nil {
				slog.Error("Failed to reset routes after network change", "error", err)
				return false
			}
			slog.Info("Routes reset successfully after network change")
			return true
		}
	}

	// For other failures, let the default rebind logic handle it
	return false
}

// cleanup closes all connections and cleans up resources
func (cm *connectionManager) cleanup() {
	slog.Info("Explicitly disconnecting from server...", "layer", "ssh")
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
	startSOCKS5Server(ctx, cfg.ListenAddr, connMgr.getSSHClient, "socks5")
	<-ctx.Done()
	return nil
}

// startSOCKS5Server is a helper that starts a SOCKS5 server with the given configuration
func startSOCKS5Server(ctx context.Context, listenAddr string, getClient func() *ssh.Client, layer string) {
	go func() {
		err := socks5.ServeSOCKS5(ctx, listenAddr,
			func(addr string) (net.Conn, error) {
				client := getClient()
				if client == nil {
					return nil, fmt.Errorf("ssh client not connected")
				}
				return socks5.DialTCP(client, addr)
			},
			func() (net.Addr, io.Closer, error) {
				client := getClient()
				if client == nil {
					return nil, nil, fmt.Errorf("ssh client not connected")
				}
				return socks5.DialUDP(client, "127.0.0.1")
			})

		if err != nil {
			slog.Error("SOCKS5 proxy server stopped", "layer", layer, "error", err)
		}
	}()

	slog.Info("SOCKS5 TCP/UDP proxy listening", "layer", layer, "addr", listenAddr)
}

// startTUNTunnel starts the TUN tunnel with fallback to SOCKS5
func runTUNLoop(ctx context.Context, connMgr *connectionManager, tunCfg *tun.Config, routes string, autoRoute bool, serverAddr string, fallbackCh chan<- struct{}) {
	tunFailed := false
	for {
		client := connMgr.getSSHClient()
		if client == nil {
			slog.Warn("Waiting for SSH connection before starting TUN...")
			time.Sleep(1 * time.Second)
			continue
		}

		err := tun.ServeTUN(ctx, client, tunCfg, routes, autoRoute, serverAddr)
		if err != nil {
			// Check if server doesn't support TUN mode
			if strings.Contains(err.Error(), "channel type") && strings.Contains(err.Error(), "not supported") {
				if !tunFailed {
					slog.Warn("Server does not support TUN mode, falling back to SOCKS5...")
					tunFailed = true
					select {
					case fallbackCh <- struct{}{}:
					default:
					}
				}
				return
			}
			slog.Error("TUN tunnel stopped", "error", err)
		}

		select {
		case <-ctx.Done():
			return
		default:
			slog.Info("Restarting TUN tunnel...", "delay", config.DefaultReconnectRetryWait)
			time.Sleep(config.DefaultReconnectRetryWait)
		}
	}
}

func startSOCKS5Fallback(ctx context.Context, listenAddr string, connMgr *connectionManager) {
	startSOCKS5Server(ctx, listenAddr, connMgr.getSSHClient, "fallback")
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

	// Setup route manager for handling route changes
	connMgr.routeManager = tun.NewRouteManager(cfg.ServerAddr, cfg.TUN.Name, slog.Default())

	fallbackToSOCKS5 := make(chan struct{}, 1)

	// Start TUN tunnel loop
	go runTUNLoop(ctx, connMgr, tunCfg, cfg.TUN.Routes, cfg.TUN.AutoRoute, cfg.ServerAddr, fallbackToSOCKS5)
	slog.Info("TUN tunnel starting", "device", tunCfg.Name)

	// Monitor for fallback signal
	go monitorTUNFallback(ctx, fallbackToSOCKS5, cfg.ListenAddr, connMgr)

	<-ctx.Done()
	return nil
}
