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

	"uproxy/internal/kcp"
	"uproxy/internal/socks5"
	"uproxy/internal/tun"
	"uproxy/internal/uproxy"
)

func serverCmd() *cobra.Command {
	var listenAddr, outbound, logLevel, logFormat string
	var idleTimeout, proxyDialTimeout, reconnectInterval time.Duration
	var tcpBufSize, udpSockBuf int
	var kcpCfg kcp.Config

	// SSH configuration
	var sshDir, sshPrivateKey, sshAuthorizedKeys string

	// TUN configuration for server side
	var tunName, tunIP, tunNetmask, tunIPv6 string
	var tunMTU int
	var autoRoute *bool

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run uproxy server (KCP+SSH SOCKS5/TUN server)",
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

			return runServer(listenAddr, outbound, idleTimeout, proxyDialTimeout, reconnectInterval, udpSockBuf, &kcpCfg, tunCfg, sshDir, sshPrivateKey, sshAuthorizedKeys, *autoRoute)
		},
	}

	cmd.Flags().StringVarP(&listenAddr, "listen", "l", ":6000", "Listen address")
	cmd.Flags().StringVarP(&outbound, "outbound", "o", "", "Outbound interface for dialing targets (e.g., tun0)")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	cmd.Flags().StringVar(&logFormat, "log-format", "console", "Log format (console, json)")

	// SSH configuration flags
	cmd.Flags().StringVar(&sshDir, "ssh-dir", "", "SSH directory (default: ~/.ssh)")
	cmd.Flags().StringVar(&sshPrivateKey, "ssh-private-key", "", "SSH private key file (default: ~/.ssh/id_ed25519 or ~/.ssh/id_rsa)")
	cmd.Flags().StringVar(&sshAuthorizedKeys, "ssh-authorized-keys", "", "SSH authorized_keys file (default: ~/.ssh/authorized_keys)")

	cmd.Flags().DurationVar(&idleTimeout, "idle-timeout", 1*time.Hour, "Idle timeout before giving up on network")
	cmd.Flags().DurationVar(&proxyDialTimeout, "proxy-dial-timeout", 5*time.Second, "Timeout for dialing upstream SOCKS5 targets")
	cmd.Flags().DurationVar(&reconnectInterval, "reconnect-interval", 1*time.Second, "Interval to retry binding UDP socket on network drop")

	cmd.Flags().IntVar(&tcpBufSize, "tcp-buf", 32768, "TCP copy buffer size per SOCKS5 stream")
	cmd.Flags().IntVar(&udpSockBuf, "udp-sockbuf", 4194304, "UDP socket buffer size")

	cmd.Flags().IntVar(&kcpCfg.NoDelay, "kcp-nodelay", 1, "KCP nodelay mode")
	cmd.Flags().IntVar(&kcpCfg.Interval, "kcp-interval", 10, "KCP timer interval in ms")
	cmd.Flags().IntVar(&kcpCfg.Resend, "kcp-resend", 2, "KCP fast resend mode")
	cmd.Flags().IntVar(&kcpCfg.NoCongestionCtrl, "kcp-nc", 1, "KCP disable congestion control")
	cmd.Flags().IntVar(&kcpCfg.SndWnd, "kcp-sndwnd", 4096, "KCP send window")
	cmd.Flags().IntVar(&kcpCfg.RcvWnd, "kcp-rcvwnd", 4096, "KCP receive window")
	cmd.Flags().IntVar(&kcpCfg.MTU, "kcp-mtu", 1350, "KCP MTU")

	// TUN mode flags (server side)
	cmd.Flags().StringVar(&tunName, "tun-name", "tun0", "TUN device name for server")
	cmd.Flags().StringVar(&tunIP, "tun-ip", "172.27.66.1", "TUN interface IPv4 address for server")
	cmd.Flags().StringVar(&tunNetmask, "tun-netmask", "255.255.255.0", "TUN interface netmask")
	cmd.Flags().StringVar(&tunIPv6, "tun-ipv6", "fd42:cafe:beef::1/64", "TUN interface IPv6 address with prefix (e.g., fd42:cafe:beef::1/64)")
	cmd.Flags().IntVar(&tunMTU, "tun-mtu", 1280, "TUN interface MTU")
	autoRoute = cmd.Flags().Bool("auto-route", true, "Automatically configure NAT and IP forwarding (server) or routing (client)")

	return cmd
}

func runServer(listenAddr, outbound string, idleTimeout, proxyDialTimeout, reconnectInterval time.Duration, udpSockBuf int, kcpCfg *kcp.Config, tunCfg *tun.Config, sshDir, sshPrivateKey, sshAuthorizedKeys string, autoRoute bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signer, err := uproxy.LoadPrivateKey(sshDir, sshPrivateKey)
	if err != nil {
		return err
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

	packetConn := uproxy.NewResilientPacketConn(listenAddr, "", reconnectInterval, udpSockBuf, true) // serverMode=true: no connectivity monitoring
	var activeClientsMu sync.Mutex
	activeClients := make(map[*ssh.ServerConn]struct{})

	// Initialize TUN manager (shared by all clients) - only if running as root
	var tunManager *tun.TUNManager
	if !uproxy.IsRoot() {
		slog.Info("TUN mode disabled (not running as root). Only SOCKS5 mode available.")
		slog.Info("To enable TUN mode, run with: sudo uproxy server ...")
	} else if tunCfg != nil && tunCfg.IP != "" {
		tunManager, err = tun.NewTUNManager(tunCfg, outbound, autoRoute)
		if err != nil {
			slog.Warn("Failed to initialize TUN manager (TUN mode disabled)", "error", err)
			tunManager = nil
		} else {
			slog.Info("TUN manager initialized (running as root)", "device", tunCfg.Name, "ipv4", tunCfg.IP, "ipv6", tunCfg.IPv6, "auto_route", autoRoute)
		}
	} else {
		slog.Info("TUN mode not configured. Only SOCKS5 mode available.")
		slog.Info("To enable TUN mode, run with: sudo uproxy server --tun-ip <ip> ...")
	}

	listener, err := kcp.ServeConn(packetConn)
	if err != nil {
		if tunManager != nil {
			tunManager.Close()
		}
		return err
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
		session.SetDeadLink(0) // 0 = disabled, connectivity monitor handles all timeouts

		go handleSSHConnection(ctx, conn, config, outbound, proxyDialTimeout, tunManager, &activeClientsMu, activeClients)
	}
}

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
