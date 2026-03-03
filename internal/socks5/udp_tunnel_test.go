package socks5

import (
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/ssh"
	"uproxy/internal/config"
	"uproxy/internal/testutil"
)

func TestParseSOCKS5UDPHeaderShortDomain(t *testing.T) {
	// RSV(2) FRAG(1) ATYP(1) LEN(1) HOST(1) PORT(2) PAYLOAD(1)
	packet := []byte{0x00, 0x00, 0x00, config.SOCKS5AddressDomain, 0x01, 'a', 0x00, 0x35, 0xff}

	target, payload, header, err := parseSOCKS5UDPHeader(packet)
	if err != nil {
		t.Fatalf("parseSOCKS5UDPHeader failed: %v", err)
	}
	if target != "a:53" {
		t.Fatalf("unexpected target: %s", target)
	}
	if len(payload) != 1 || payload[0] != 0xff {
		t.Fatalf("unexpected payload: %v", payload)
	}
	if len(header) != 8 {
		t.Fatalf("unexpected header size: %d", len(header))
	}
}

func TestParseSOCKS5UDPHeaderTooShort(t *testing.T) {
	_, _, _, err := parseSOCKS5UDPHeader([]byte{0x00, 0x00, 0x00})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestUDPSessionManagerCloseAllSessions(t *testing.T) {
	mgr := &udpSessionManager{
		sessions: make(map[string]ssh.Channel),
	}

	ch1 := testutil.NewMockSSHChannel()
	ch2 := testutil.NewMockSSHChannel()
	mgr.sessions["1.1.1.1:53"] = ch1
	mgr.sessions["8.8.8.8:53"] = ch2

	mgr.closeAllSessions()

	if !ch1.Closed {
		t.Fatal("expected first channel to be closed")
	}
	if !ch2.Closed {
		t.Fatal("expected second channel to be closed")
	}
	if len(mgr.sessions) != 0 {
		t.Fatalf("expected sessions map to be empty, got %d", len(mgr.sessions))
	}
}
