package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"sync"
	"uproxy/internal/kcp"
	"uproxy/internal/socks5"
	"uproxy/internal/tun"
	"uproxy/internal/uproxy"
)

func main() {
	var listenAddr, outbound, logLevel, logFormat string
	var idleTimeout, proxyDialTimeout, reconnectInterval time.Duration
	var tcpBufSize, udpSockBuf int
	var kcpCfg kcp.Config

	// SSH configuration
	var sshDir, sshPrivateKey, sshAuthorizedKeys string

	// TUN configuration for server side
	var tunName, tunIP, tunNetmask, tunIPv6 string
	var tunMTU int

	var rootCmd = &cobra.Command{
		Use:   "uproxy-server",
		Short: "Highly resilient KCP+SSH SOCKS5 server",
		RunE: func(cmd *cobra.Command, args []string) error {
			uproxy.InitLogger(logLevel, logFormat)
			uproxy.TCPBufSize = tcpBufSize

			tunCfg := &tun.Config{
				Name:    tunName,
				IP:      tunIP,
				Netmask: tunNetmask,
				IPv6:    tunIPv6,
				MTU:     tunMTU,
			}

			return runServer(listenAddr, outbound, idleTimeout, proxyDialTimeout, reconnectInterval, udpSockBuf, &kcpCfg, tunCfg, sshDir, sshPrivateKey, sshAuthorizedKeys)
		},
	}

	rootCmd.Flags().StringVarP(&listenAddr, "listen", "l", ":6000", "Listen address")
	rootCmd.Flags().StringVarP(&outbound, "outbound", "o", "", "Outbound interface for dialing targets (e.g., tun0)")
	rootCmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.Flags().StringVar(&logFormat, "log-format", "console", "Log format (console, json)")

	// SSH configuration flags
	rootCmd.Flags().StringVar(&sshDir, "ssh-dir", "", "SSH directory (default: ~/.ssh)")
	rootCmd.Flags().StringVar(&sshPrivateKey, "ssh-private-key", "", "SSH private key file (default: ~/.ssh/id_ed25519 or ~/.ssh/id_rsa)")
	rootCmd.Flags().StringVar(&sshAuthorizedKeys, "ssh-authorized-keys", "", "SSH authorized_keys file (default: ~/.ssh/authorized_keys)")

	rootCmd.Flags().DurationVar(&idleTimeout, "idle-timeout", 1*time.Hour, "Idle timeout before giving up on network")
	rootCmd.Flags().DurationVar(&proxyDialTimeout, "proxy-dial-timeout", 5*time.Second, "Timeout for dialing upstream SOCKS5 targets")
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

	// TUN mode flags (server side)
	rootCmd.Flags().StringVar(&tunName, "tun-name", "tun0", "TUN device name for server")
	rootCmd.Flags().StringVar(&tunIP, "tun-ip", "10.0.0.1", "TUN interface IPv4 address for server")
	rootCmd.Flags().StringVar(&tunNetmask, "tun-netmask", "255.255.255.0", "TUN interface netmask")
	rootCmd.Flags().StringVar(&tunIPv6, "tun-ipv6", "", "TUN interface IPv6 address with prefix (e.g., fd00::1/64)")
	rootCmd.Flags().IntVar(&tunMTU, "tun-mtu", 1280, "TUN interface MTU")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// runServer initializes the ResilientPacketConn, KCP listener, and SSH subsystem.
func runServer(listenAddr, outbound string, idleTimeout, proxyDialTimeout, reconnectInterval time.Duration, udpSockBuf int, kcpCfg *kcp.Config, tunCfg *tun.Config, sshDir, sshPrivateKey, sshAuthorizedKeys string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signer, err := uproxy.LoadPrivateKey(sshDir, sshPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to load SSH key: %v", err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			slog.Info("Client attempting SSH authentication",
				"remote_addr", conn.RemoteAddr(),
				"user", conn.User(),
				"key_type", key.Type(),
				"fingerprint", ssh.FingerprintSHA256(key))

			if err := uproxy.CheckAuthorizedKeys(key, sshDir, sshAuthorizedKeys); err != nil {
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
	config.AddHostKey(signer)

	packetConn := uproxy.NewResilientPacketConn(listenAddr, "", reconnectInterval, udpSockBuf)
	var activeClientsMu sync.Mutex
	activeClients := make(map[*ssh.ServerConn]struct{})

	// Initialize TUN manager (shared by all clients) - only if running as root
	var tunManager *tun.TUNManager
	if !uproxy.IsRoot() {
		slog.Info("TUN mode disabled (not running as root). Only SOCKS5 mode available.")
		slog.Info("To enable TUN mode, run with: sudo uproxy-server ...")
	} else if tunCfg != nil && tunCfg.IP != "" {
		tunManager, err = tun.NewTUNManager(tunCfg, outbound)
		if err != nil {
			slog.Warn("Failed to initialize TUN manager (TUN mode disabled)", "error", err)
			tunManager = nil
		} else {
			slog.Info("TUN manager initialized (running as root)", "device", tunCfg.Name, "ipv4", tunCfg.IP, "ipv6", tunCfg.IPv6)
		}
	} else {
		slog.Info("TUN mode not configured. Only SOCKS5 mode available.")
		slog.Info("To enable TUN mode, run with: sudo uproxy-server --tun-ip <ip> ...")
	}

	listener, err := kcp.ServeConn(packetConn)
	if err != nil {
		if tunManager != nil {
			tunManager.Close()
		}
		return fmt.Errorf("failed to listen on KCP: %v", err)
	}
	slog.Info("Listening on KCP", "addr", listenAddr)

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		slog.Info("Shutting down...")
		activeClientsMu.Lock()
		for client := range activeClients {
			client.Close()
		}
		activeClientsMu.Unlock()
		time.Sleep(200 * time.Millisecond)

		// Close TUN manager
		if tunManager != nil {
			tunManager.Close()
		}

		listener.Close()
		packetConn.Close()
		cancel()
	}()

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

		session := conn
		session.SetStreamMode(true)
		kcpCfg.Apply(session)
		session.SetDeadLink(uint32(idleTimeout/time.Second) * 2)

		go handleSSHConnection(ctx, uproxy.NewIdleTimeoutConn(conn, idleTimeout), config, outbound, proxyDialTimeout, tunManager, &activeClientsMu, activeClients)
	}
}

// handleSSHConnection upgrades the KCP transport to an SSH connection and multiplexes SOCKS5 channels.
func handleSSHConnection(ctx context.Context, conn net.Conn, config *ssh.ServerConfig, outbound string, dialTimeout time.Duration, tunManager *tun.TUNManager, activeClientsMu *sync.Mutex, activeClients map[*ssh.ServerConn]struct{}) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		slog.Error("SSH handshake failed", "error", err)
		conn.Close()
		return
	}
	slog.Info("Client connected (SSH auth success)", "layer", "ssh", "addr", sshConn.RemoteAddr().String())

	activeClientsMu.Lock()
	activeClients[sshConn] = struct{}{}
	activeClientsMu.Unlock()

	defer func() {
		activeClientsMu.Lock()
		delete(activeClients, sshConn)
		activeClientsMu.Unlock()
	}()

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case socks5.ChannelTypeTCP:
			channel, requests, err := newChan.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(requests)
			go socks5.HandleTCP(ctx, channel, sshConn.RemoteAddr(), outbound, dialTimeout)

		case socks5.ChannelTypeUDP:
			channel, requests, err := newChan.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(requests)
			go socks5.HandleUDP(ctx, channel, outbound, dialTimeout)

		case tun.ChannelTypeTUN:
			channel, requests, err := newChan.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(requests)
			go tun.HandleTUN(channel, tunManager)

		default:
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}
