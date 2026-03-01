package validation

import (
	"testing"

	"uproxy/internal/config"
)

func BenchmarkValidateIPv4Packet(b *testing.B) {
	// Valid IPv4 packet
	packet := []byte{
		0x45, 0x00, 0x00, 0x28, // Version, IHL, TOS, Total Length
		0x00, 0x01, 0x00, 0x00, // ID, Flags, Fragment Offset
		0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum
		0xc0, 0xa8, 0x01, 0x01, // Source IP
		0xc0, 0xa8, 0x01, 0x02, // Dest IP
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateIPv4Packet(packet)
	}
}

func BenchmarkValidateIPv6Packet(b *testing.B) {
	// Valid IPv6 packet
	packet := make([]byte, 40)
	packet[0] = 0x60 // Version 6
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateIPv6Packet(packet)
	}
}

func BenchmarkValidateIPPacket(b *testing.B) {
	// Valid IPv4 packet
	packet := []byte{
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00,
		0xc0, 0xa8, 0x01, 0x01,
		0xc0, 0xa8, 0x01, 0x02,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateIPPacket(packet)
	}
}

func BenchmarkValidateSOCKS5Version(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateSOCKS5Version(0x05)
	}
}

func BenchmarkValidateSOCKS5AddressType(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateSOCKS5AddressType(0x01)
	}
}

func BenchmarkValidateSOCKS5Command(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateSOCKS5Command(0x01)
	}
}

func BenchmarkValidateClientMode(b *testing.B) {
	cfg := &config.ClientConfig{
		Mode:       "tun",
		ListenAddr: "127.0.0.1:1080",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateClientMode(cfg)
	}
}

func BenchmarkValidateIPAddress(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateIPAddress("192.168.1.1")
	}
}

func BenchmarkValidatePort(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidatePort(8080)
	}
}
