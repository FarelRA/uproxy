package tun

import (
	"bytes"
	"strings"
	"testing"

	"uproxy/internal/framing"
	"uproxy/internal/testutil"
)

func TestReadServerAssignedIPsFramed(t *testing.T) {
	ch := testutil.NewMockConn()
	if err := framing.WriteFramed(ch.ReadBuf, []byte("IPv4:10.0.0.2\nIPv6:fd00::2/64\n")); err != nil {
		t.Fatalf("failed to write framed test payload: %v", err)
	}

	ipv4, ipv6, err := readServerAssignedIPs(ch)
	if err != nil {
		t.Fatalf("readServerAssignedIPs failed: %v", err)
	}
	if ipv4 != "10.0.0.2" {
		t.Fatalf("unexpected IPv4: %q", ipv4)
	}
	if ipv6 != "fd00::2/64" {
		t.Fatalf("unexpected IPv6: %q", ipv6)
	}
}

func TestReadServerAssignedIPsServerError(t *testing.T) {
	ch := testutil.NewMockConn()
	if err := framing.WriteFramed(ch.ReadBuf, []byte("ERROR: allocation failed\n")); err != nil {
		t.Fatalf("failed to write framed test payload: %v", err)
	}

	_, _, err := readServerAssignedIPs(ch)
	if err == nil {
		t.Fatal("expected server error")
	}
	if !strings.Contains(err.Error(), "allocation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadServerAssignedIPsMissingIPv4(t *testing.T) {
	ch := testutil.NewMockConn()
	if err := framing.WriteFramed(ch.ReadBuf, []byte("IPv6:fd00::2/64\n")); err != nil {
		t.Fatalf("failed to write framed test payload: %v", err)
	}

	_, _, err := readServerAssignedIPs(ch)
	if err == nil {
		t.Fatal("expected missing IPv4 error")
	}
	if !strings.Contains(err.Error(), "did not assign IPv4") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadServerAssignedIPsInvalidFrame(t *testing.T) {
	ch := testutil.NewMockConn()
	ch.ReadBuf = bytes.NewBufferString("IPv4:10.0.0.2\n")

	_, _, err := readServerAssignedIPs(ch)
	if err == nil {
		t.Fatal("expected frame read error")
	}
}
