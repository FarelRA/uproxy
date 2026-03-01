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

	"uproxy/internal/kcp"
	"uproxy/internal/socks5"
	"uproxy/internal/tun"
	"uproxy/internal/uproxy"
)

func main() {
	var listenAddr, serverAddr string
	var logLevel, logFormat string
	var mode string
	var idleTimeout, sshTimeout, reconnectInterval time.Duration
	var tcpBufSize, udpSockBuf int
	var kcpCfg kcp.Config

	// TUN mode configuration
	var tunName, tunIP, tunNetmask, tunIPv6, tunRoutes string
	var tunMTU int

	var rootCmd = &cobra.Command{
		Use:   "uproxy-client",
		Short: "Highly resilient KCP+SSH proxy client (SOCKS5 or TUN mode)",
		RunE: func(cmd *cobra.Command, args []string) error {
			uproxy.InitLogger(logLevel, logFormat)
			uproxy.TCPBufSize = tcpBufSize

			tunCfg := tun.Config{
				Name:    tunName,
				IP:      tunIP,
				Netmask: tunNetmask,
				IPv6:    tunIPv6,
				MTU:     tunMTU,
			}

			return runClient(mode, listenAddr, serverAddr, idleTimeout, sshTimeout, reconnectInterval, udpSockBuf, &kcpCfg, &tunCfg, tunRoutes)
		},
	}

	rootCmd.Flags().StringVar(&mode, "mode", "auto", "Operating mode: auto (default), socks5, or tun. Auto selects tun if root, socks5 otherwise")
	rootCmd.Flags().StringVarP(&listenAddr, "listen", "l", "127.0.0.1:1080", "Local SOCKS5 listen address (socks5 mode only)")
	rootCmd.Flags().StringVarP(&serverAddr, "server", "s", "", "Remote server address (e.g., 203.0.113.50:6000)")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&logFormat, "log-format", "console", "Log format (console, json)")

	// TUN mode flags
	rootCmd.Flags().StringVar(&tunName, "tun-name", "utun0", "TUN device name (tun mode only)")
	rootCmd.Flags().StringVar(&tunIP, "tun-ip", "", "TUN interface IPv4 address (required for tun mode)")
	rootCmd.Flags().StringVar(&tunNetmask, "tun-netmask", "255.255.255.0", "TUN interface netmask (tun mode only)")
	rootCmd.Flags().StringVar(&tunIPv6, "tun-ipv6", "", "TUN interface IPv6 address with prefix (e.g., fd00::2/64)")
	rootCmd.Flags().IntVar(&tunMTU, "tun-mtu", 1400, "TUN interface MTU (tun mode only)")
	rootCmd.Flags().StringVar(&tunRoutes, "tun-routes", "", "Comma-separated routes to add (e.g., 0.0.0.0/0,8.8.8.8/32,::/0)")

	rootCmd.Flags().DurationVar(&idleTimeout, "idle-timeout", 1*time.Hour, "Idle timeout before giving up on network")
	rootCmd.Flags().DurationVar(&sshTimeout, "ssh-timeout", 10*time.Second, "Timeout for the initial SSH handshake")
	rootCmd.Flags().DurationVar(&reconnectInterval, "reconnect-interval", 1*time.Second, "Interval to retry binding UDP socket on network drop")

	rootCmd.Flags().IntVar(&tcpBufSize, "tcp-buf", 32768, "TCP copy buffer size per SOCKS5 stream")
	rootCmd.Flags().IntVar(&udpSockBuf, "udp-sockbuf", 4194304, "UDP socket buffer size")

	rootCmd.Flags().IntVar(&kcpCfg.NoDelay, "kcp-nodelay", 1, "KCP nodelay mode")
	rootCmd.Flags().IntVar(&kcpCfg.Interval, "kcp-interval", 10, "KCP timer interval in ms")
	rootCmd.Flags().IntVar(&kcpCfg.Resend, "kcp-resend", 2, "KCP fast resend mode")
	rootCmd.Flags().IntVar(&kcpCfg.NoCongestionCtrl, "kcp-nc", 1, "KCP disable congestion control")
	rootCmd.Flags().IntVar(&kcpCfg.SndWnd, "kcp-sndwnd", 4096, "KCP send window")
	rootCmd.Flags().IntVar(&kcpCfg.RcvWnd, "kcp-rcvwnd", 4096, "KCP receive window")
	rootCmd.Flags().IntVar(&kcpCfg.MTU, "kcp-mtu", 1350, "KCP MTU")

	rootCmd.MarkFlagRequired("server")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// runClient initializes the background connection loop and the foreground proxy (SOCKS5 or TUN).
func runClient(mode, listenAddr, serverAddr string, idleTimeout, sshTimeout, reconnectInterval time.Duration, udpSockBuf int, kcpCfg *kcp.Config, tunCfg *tun.Config, tunRoutes string) error {
	// Auto-detect mode based on privileges
	if mode == "auto" {
		if uproxy.IsRoot() {
			mode = "tun"
			slog.Info("Auto-selected TUN mode (running as root)")
		} else {
			mode = "socks5"
			slog.Info("Auto-selected SOCKS5 mode (not running as root)")
		}
	}

	// Validate mode-specific requirements
	if mode == "socks5" {
		if listenAddr == "" {
			return fmt.Errorf("--listen is required for socks5 mode")
		}
	}
	if mode == "tun" {
		if !uproxy.IsRoot() {
			return fmt.Errorf("TUN mode requires root privileges. Run with sudo or use --mode socks5")
		}
		if tunCfg.IP == "" {
			return fmt.Errorf("--tun-ip is required for tun mode")
		}
	}
	if mode != "socks5" && mode != "tun" {
		return fmt.Errorf("invalid mode: %s (must be 'auto', 'socks5', or 'tun')", mode)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signer, err := uproxy.LoadPrivateKey()
	if err != nil {
		return fmt.Errorf("failed to load SSH key: %v", err)
	}

	var mu sync.RWMutex
	var currentSSHClient *ssh.Client
	var currentKCPConn *kcp.UDPSession
	var currentPacketConn *uproxy.ResilientPacketConn

	defer func() {
		slog.Info("Explicitly disconnecting from server...", "layer", "ssh")
		mu.Lock()
		defer mu.Unlock()
		if currentSSHClient != nil {
			currentSSHClient.Close()
		}
		if currentKCPConn != nil {
			currentKCPConn.Close()
		}
		if currentPacketConn != nil {
			/* Allow a brief moment for the SSH DISCONNECT and KCP teardown packets to flush over the network */
			time.Sleep(200 * time.Millisecond)
			currentPacketConn.Close()
		}
	}()

	var connect func()
	connect = func() {
		mu.Lock()
		defer mu.Unlock()

		if currentSSHClient != nil {
			_ = currentSSHClient.Close()
		}
		if currentKCPConn != nil {
			_ = currentKCPConn.Close()
		}
		if currentPacketConn != nil {
			_ = currentPacketConn.Close()
		}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			slog.Info("Dialing server", "addr", serverAddr)
			packetConn := uproxy.NewResilientPacketConn("", "", reconnectInterval, udpSockBuf)
			kcpConn, err := kcp.NewConn(serverAddr, packetConn)
			if err != nil {
				slog.Error("Dial KCP failed, retrying in 3s...", "error", err)
				packetConn.Close()
				time.Sleep(3 * time.Second)
				continue
			}

			kcpConn.SetStreamMode(true)
			kcpCfg.Apply(kcpConn)
			kcpConn.SetDeadLink(uint32(idleTimeout/time.Second) * 2)

			config := &ssh.ClientConfig{
				User: "proxy",
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(signer),
				},
				HostKeyCallback: uproxy.VerifyKnownHost,
				Timeout:         sshTimeout,
			}

			slog.Info("Attempting SSH authentication",
				"server", serverAddr,
				"user", "proxy",
				"key_type", signer.PublicKey().Type(),
				"fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))

			sshClientConn, sshChans, sshReqs, err := ssh.NewClientConn(uproxy.NewIdleTimeoutConn(kcpConn, idleTimeout), serverAddr, config)
			if err != nil {
				slog.Error("SSH handshake failed, retrying in 3s...",
					"error", err,
					"key_type", signer.PublicKey().Type(),
					"fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
				kcpConn.Close()
				packetConn.Close()
				time.Sleep(3 * time.Second)
				continue
			}

			sshClient := ssh.NewClient(sshClientConn, sshChans, sshReqs)
			slog.Info("Connected to server via KCP+SSH (Resilient)", "layer", "ssh")

			currentSSHClient = sshClient
			currentKCPConn = kcpConn
			currentPacketConn = packetConn

			go func(c *ssh.Client) {
				_ = c.Wait()
				slog.Info("SSH connection died. Reconnecting...")
				go connect()
			}(sshClient)

			return
		}
	}

	// Spin up connection in background
	go connect()

	// Start proxy based on mode
	slog.Info("Starting proxy", "mode", mode, "listenAddr", listenAddr)
	if mode == "socks5" {
		// Start SOCKS5 Server
		go func() {
			err := socks5.ServeSOCKS5(ctx, listenAddr, func(addr string) (net.Conn, error) {
				mu.RLock()
				client := currentSSHClient
				mu.RUnlock()
				if client == nil {
					return nil, fmt.Errorf("ssh client not connected")
				}
				return socks5.DialTCP(client, addr)
			}, func() (net.Addr, io.Closer, error) {
				mu.RLock()
				client := currentSSHClient
				mu.RUnlock()
				if client == nil {
					return nil, nil, fmt.Errorf("ssh client not connected")
				}
				return socks5.DialUDP(client, "127.0.0.1")
			})

			if err != nil {
				slog.Error("SOCKS5 proxy server stopped", "error", err)
			}
		}()
		slog.Info("SOCKS5 TCP/UDP proxy listening", "addr", listenAddr)
	} else if mode == "tun" {
		// Start TUN tunnel with fallback to SOCKS5
		fallbackToSOCKS5 := make(chan struct{}, 1)
		go func() {
			tunFailed := false
			for {
				mu.RLock()
				client := currentSSHClient
				mu.RUnlock()

				if client == nil {
					slog.Warn("Waiting for SSH connection before starting TUN...")
					time.Sleep(1 * time.Second)
					continue
				}

				err := tun.ServeTUN(ctx, client, tunCfg, tunRoutes)
				if err != nil {
					// Check if server doesn't support TUN mode
					if strings.Contains(err.Error(), "channel type") && strings.Contains(err.Error(), "not supported") {
						if !tunFailed {
							slog.Warn("Server does not support TUN mode, falling back to SOCKS5...")
							tunFailed = true
							select {
							case fallbackToSOCKS5 <- struct{}{}:
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
					slog.Info("Restarting TUN tunnel in 3s...")
					time.Sleep(3 * time.Second)
				}
			}
		}()
		slog.Info("TUN tunnel starting", "device", tunCfg.Name, "ip", tunCfg.IP)

		// Monitor for fallback signal
		go func() {
			select {
			case <-fallbackToSOCKS5:
				if listenAddr == "" {
					listenAddr = "127.0.0.1:1080"
					slog.Info("Using default SOCKS5 listen address", "addr", listenAddr)
				}

				// Start SOCKS5 server as fallback
				go func() {
					err := socks5.ServeSOCKS5(ctx, listenAddr, func(addr string) (net.Conn, error) {
						mu.RLock()
						client := currentSSHClient
						mu.RUnlock()
						if client == nil {
							return nil, fmt.Errorf("ssh client not connected")
						}
						return socks5.DialTCP(client, addr)
					}, func() (net.Addr, io.Closer, error) {
						mu.RLock()
						client := currentSSHClient
						mu.RUnlock()
						if client == nil {
							return nil, nil, fmt.Errorf("ssh client not connected")
						}
						return socks5.DialUDP(client, "127.0.0.1")
					})

					if err != nil {
						slog.Error("SOCKS5 proxy server stopped", "error", err)
					}
				}()
				slog.Info("SOCKS5 TCP/UDP proxy listening (fallback mode)", "addr", listenAddr)
			case <-ctx.Done():
				return
			}
		}()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	slog.Info("Shutting down...")

	cancel()
	return nil
}
