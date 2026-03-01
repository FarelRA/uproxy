package tun

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	TCPTimeout  = 5 * time.Minute
	UDPTimeout  = 30 * time.Second
	ICMPTimeout = 10 * time.Second
)

// FlowHandler manages active network flows
type FlowHandler struct {
	mu       sync.RWMutex
	flows    map[string]*Flow
	channel  ssh.Channel
	ctx      context.Context
	cancel   context.CancelFunc
	outbound string // Optional outbound interface
}

// Flow represents an active network connection or session
type Flow struct {
	Key       FlowKey
	Conn      net.Conn
	LastSeen  time.Time
	Cancel    context.CancelFunc
	WriteChan chan []byte
}

// NewFlowHandler creates a new flow handler
func NewFlowHandler(channel ssh.Channel, outbound string) *FlowHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &FlowHandler{
		flows:    make(map[string]*Flow),
		channel:  channel,
		ctx:      ctx,
		cancel:   cancel,
		outbound: outbound,
	}
}

// HandlePacket processes an incoming IP packet
func (h *FlowHandler) HandlePacket(packet []byte) error {
	info, err := ParsePacket(packet)
	if err != nil {
		return fmt.Errorf("failed to parse packet: %w", err)
	}

	switch info.Protocol {
	case ProtocolTCP:
		return h.handleTCP(packet, info)
	case ProtocolUDP:
		return h.handleUDP(packet, info)
	case ProtocolICMP:
		return h.handleICMP(packet, info)
	case ProtocolICMPv6:
		return h.handleICMPv6(packet, info)
	default:
		slog.Debug("Unsupported protocol", "protocol", ProtocolName(info.Protocol))
		return nil
	}
}

// handleTCP processes TCP packets
func (h *FlowHandler) handleTCP(packet []byte, info *PacketInfo) error {
	flowKey := info.FlowKey.String()

	h.mu.RLock()
	flow, exists := h.flows[flowKey]
	h.mu.RUnlock()

	if !exists {
		// New TCP connection
		return h.createTCPFlow(packet, info)
	}

	// Update last seen time
	flow.LastSeen = time.Now()

	// Send packet to flow handler
	select {
	case flow.WriteChan <- packet:
	default:
		slog.Warn("Flow write channel full", "flow", flowKey)
	}

	return nil
}

// createTCPFlow creates a new TCP flow
func (h *FlowHandler) createTCPFlow(packet []byte, info *PacketInfo) error {
	target := fmt.Sprintf("%s:%d", info.DstIP, info.DstPort)

	slog.Info("New TCP flow", "src", info.SrcIP, "src_port", info.SrcPort,
		"dst", info.DstIP, "dst_port", info.DstPort)

	// Dial the target
	dialer := &net.Dialer{
		Timeout: TCPTimeout,
	}

	// Use outbound interface if specified
	if h.outbound != "" {
		iface, err := net.InterfaceByName(h.outbound)
		if err == nil {
			addrs, err := iface.Addrs()
			if err == nil && len(addrs) > 0 {
				if ipnet, ok := addrs[0].(*net.IPNet); ok {
					dialer.LocalAddr = &net.TCPAddr{IP: ipnet.IP}
				}
			}
		}
	}

	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("failed to dial %s: %w", target, err)
	}

	// Create flow
	ctx, cancel := context.WithCancel(h.ctx)
	flow := &Flow{
		Key:       info.FlowKey,
		Conn:      conn,
		LastSeen:  time.Now(),
		Cancel:    cancel,
		WriteChan: make(chan []byte, 100),
	}

	flowKey := info.FlowKey.String()
	h.mu.Lock()
	h.flows[flowKey] = flow
	h.mu.Unlock()

	// Start flow handler goroutines
	go h.handleTCPFlow(ctx, flow, packet, info)

	return nil
}

// handleTCPFlow manages a TCP flow
func (h *FlowHandler) handleTCPFlow(ctx context.Context, flow *Flow, initialPacket []byte, info *PacketInfo) {
	defer func() {
		flow.Conn.Close()
		flow.Cancel()

		flowKey := flow.Key.String()
		h.mu.Lock()
		delete(h.flows, flowKey)
		h.mu.Unlock()

		slog.Info("TCP flow closed", "flow", flowKey)
	}()

	// Extract TCP payload from initial packet
	tcpHeaderLen := getTCPHeaderLen(initialPacket[info.HeaderLen:])
	payload := initialPacket[info.HeaderLen+tcpHeaderLen:]

	// Write initial payload if any
	if len(payload) > 0 {
		if _, err := flow.Conn.Write(payload); err != nil {
			slog.Error("Failed to write initial TCP payload", "error", err)
			return
		}
	}

	var wg sync.WaitGroup

	// Read from connection, send responses back through channel
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)

		for {
			n, err := flow.Conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					slog.Debug("TCP read error", "error", err)
				}
				return
			}

			if n > 0 {
				// Build response packet and send back
				respPacket := buildTCPResponsePacket(info, buf[:n])
				if err := writeFramed(h.channel, respPacket); err != nil {
					slog.Error("Failed to write response", "error", err)
					return
				}
			}
		}
	}()

	// Read from write channel, forward to connection
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case packet := <-flow.WriteChan:
				// Extract payload and write to connection
				tcpHeaderLen := getTCPHeaderLen(packet[info.HeaderLen:])
				payload := packet[info.HeaderLen+tcpHeaderLen:]

				if len(payload) > 0 {
					if _, err := flow.Conn.Write(payload); err != nil {
						slog.Debug("TCP write error", "error", err)
						return
					}
				}
			}
		}
	}()

	// Timeout handler
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(flow.LastSeen) > TCPTimeout {
				slog.Info("TCP flow timeout", "flow", flow.Key.String())
				return
			}
		}
	}
}

// handleUDP processes UDP packets
func (h *FlowHandler) handleUDP(packet []byte, info *PacketInfo) error {
	flowKey := info.FlowKey.String()

	h.mu.RLock()
	flow, exists := h.flows[flowKey]
	h.mu.RUnlock()

	if !exists {
		return h.createUDPFlow(packet, info)
	}

	// Update last seen time
	flow.LastSeen = time.Now()

	// Extract UDP payload
	payload := packet[info.HeaderLen+8:] // UDP header is 8 bytes

	// Send to remote
	if _, err := flow.Conn.Write(payload); err != nil {
		slog.Error("Failed to write UDP packet", "error", err)
		return err
	}

	return nil
}

// createUDPFlow creates a new UDP flow
func (h *FlowHandler) createUDPFlow(packet []byte, info *PacketInfo) error {
	target := fmt.Sprintf("%s:%d", info.DstIP, info.DstPort)

	slog.Info("New UDP flow", "src", info.SrcIP, "src_port", info.SrcPort,
		"dst", info.DstIP, "dst_port", info.DstPort)

	// Dial UDP
	conn, err := net.Dial("udp", target)
	if err != nil {
		return fmt.Errorf("failed to dial UDP %s: %w", target, err)
	}

	// Create flow
	ctx, cancel := context.WithCancel(h.ctx)
	flow := &Flow{
		Key:      info.FlowKey,
		Conn:     conn,
		LastSeen: time.Now(),
		Cancel:   cancel,
	}

	flowKey := info.FlowKey.String()
	h.mu.Lock()
	h.flows[flowKey] = flow
	h.mu.Unlock()

	// Start UDP flow handler
	go h.handleUDPFlow(ctx, flow, info)

	// Send initial packet
	payload := packet[info.HeaderLen+8:]
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("failed to write initial UDP packet: %w", err)
	}

	return nil
}

// handleUDPFlow manages a UDP flow
func (h *FlowHandler) handleUDPFlow(ctx context.Context, flow *Flow, info *PacketInfo) {
	defer func() {
		flow.Conn.Close()
		flow.Cancel()

		flowKey := flow.Key.String()
		h.mu.Lock()
		delete(h.flows, flowKey)
		h.mu.Unlock()

		slog.Info("UDP flow closed", "flow", flowKey)
	}()

	buf := make([]byte, 65535)

	// Read responses and send back
	for {
		flow.Conn.SetReadDeadline(time.Now().Add(UDPTimeout))
		n, err := flow.Conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				slog.Debug("UDP flow timeout", "flow", flow.Key.String())
			}
			return
		}

		if n > 0 {
			// Build response packet
			respPacket := buildUDPResponsePacket(info, buf[:n])
			if err := writeFramed(h.channel, respPacket); err != nil {
				slog.Error("Failed to write UDP response", "error", err)
				return
			}
		}

		flow.LastSeen = time.Now()
	}
}

// handleICMP processes ICMP packets (IPv4)
func (h *FlowHandler) handleICMP(packet []byte, info *PacketInfo) error {
	// Parse ICMP message
	msg, err := icmp.ParseMessage(ProtocolICMP, packet[info.HeaderLen:])
	if err != nil {
		return fmt.Errorf("failed to parse ICMP: %w", err)
	}

	// Only handle echo requests
	if msg.Type != ipv4.ICMPTypeEcho {
		return nil
	}

	slog.Debug("ICMP echo request", "src", info.SrcIP, "dst", info.DstIP)

	// Create ICMP connection
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	defer conn.Close()

	// Send echo request
	dstAddr, err := net.ResolveIPAddr("ip4", info.DstIP)
	if err != nil {
		return err
	}

	if _, err := conn.WriteTo(packet[info.HeaderLen:], dstAddr); err != nil {
		return fmt.Errorf("failed to send ICMP: %w", err)
	}

	// Wait for reply
	conn.SetReadDeadline(time.Now().Add(ICMPTimeout))
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("failed to read ICMP reply: %w", err)
	}

	// Build response packet
	respPacket := buildICMPResponsePacket(info, buf[:n])
	return writeFramed(h.channel, respPacket)
}

// handleICMPv6 processes ICMPv6 packets
func (h *FlowHandler) handleICMPv6(packet []byte, info *PacketInfo) error {
	msg, err := icmp.ParseMessage(ProtocolICMPv6, packet[info.HeaderLen:])
	if err != nil {
		return fmt.Errorf("failed to parse ICMPv6: %w", err)
	}

	// Only handle echo requests
	if msg.Type != ipv6.ICMPTypeEchoRequest {
		return nil
	}

	slog.Debug("ICMPv6 echo request", "src", info.SrcIP, "dst", info.DstIP)

	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return fmt.Errorf("failed to create ICMPv6 socket: %w", err)
	}
	defer conn.Close()

	dstAddr, err := net.ResolveIPAddr("ip6", info.DstIP)
	if err != nil {
		return err
	}

	if _, err := conn.WriteTo(packet[info.HeaderLen:], dstAddr); err != nil {
		return fmt.Errorf("failed to send ICMPv6: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(ICMPTimeout))
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("failed to read ICMPv6 reply: %w", err)
	}

	respPacket := buildICMPv6ResponsePacket(info, buf[:n])
	return writeFramed(h.channel, respPacket)
}

// Close closes all active flows
func (h *FlowHandler) Close() {
	h.cancel()

	h.mu.Lock()
	defer h.mu.Unlock()

	for _, flow := range h.flows {
		flow.Cancel()
		flow.Conn.Close()
	}

	h.flows = make(map[string]*Flow)
}

// Helper functions for building response packets
func getTCPHeaderLen(tcpData []byte) int {
	if len(tcpData) < 12 {
		return 20 // Minimum TCP header
	}
	dataOffset := (tcpData[12] >> 4) * 4
	return int(dataOffset)
}
