package fuzz

import (
	"testing"

	"uproxy/internal/validation"
)

// FuzzValidateIPv4Packet tests IPv4 packet validation with random inputs
func FuzzValidateIPv4Packet(f *testing.F) {
	// Seed corpus with valid and invalid IPv4 packets
	f.Add([]byte{0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x00, 0x68, 0xc0, 0xa8, 0x00, 0x01})
	f.Add([]byte{0x45, 0x00, 0x00, 0x14})
	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic on any input
		_ = validation.ValidateIPv4Packet(data)
	})
}

// FuzzValidateIPv6Packet tests IPv6 packet validation with random inputs
func FuzzValidateIPv6Packet(f *testing.F) {
	// Seed corpus with valid and invalid IPv6 packets
	validIPv6 := []byte{
		0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
	f.Add(validIPv6)
	f.Add([]byte{0x60, 0x00, 0x00, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic on any input
		_ = validation.ValidateIPv6Packet(data)
	})
}

// FuzzValidateIPPacket tests generic IP packet validation with random inputs
func FuzzValidateIPPacket(f *testing.F) {
	// Seed corpus with various packet types
	f.Add([]byte{0x45, 0x00, 0x00, 0x3c}) // IPv4
	f.Add([]byte{0x60, 0x00, 0x00, 0x00}) // IPv6
	f.Add([]byte{0x40})                   // Invalid version
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic on any input
		_ = validation.ValidateIPPacket(data)
	})
}

// FuzzValidateSOCKS5Version tests SOCKS5 version validation with random inputs
func FuzzValidateSOCKS5Version(f *testing.F) {
	// Seed corpus
	f.Add(byte(0x05)) // Valid SOCKS5
	f.Add(byte(0x04)) // SOCKS4
	f.Add(byte(0x00))
	f.Add(byte(0xff))

	f.Fuzz(func(t *testing.T, version byte) {
		// Should not panic on any input
		_ = validation.ValidateSOCKS5Version(version)
	})
}

// FuzzValidateSOCKS5AddressType tests SOCKS5 address type validation with random inputs
func FuzzValidateSOCKS5AddressType(f *testing.F) {
	// Seed corpus
	f.Add(byte(0x01)) // IPv4
	f.Add(byte(0x03)) // Domain
	f.Add(byte(0x04)) // IPv6
	f.Add(byte(0x00))
	f.Add(byte(0xff))

	f.Fuzz(func(t *testing.T, addrType byte) {
		// Should not panic on any input
		_ = validation.ValidateSOCKS5AddressType(addrType)
	})
}

// FuzzValidateSOCKS5Command tests SOCKS5 command validation with random inputs
func FuzzValidateSOCKS5Command(f *testing.F) {
	// Seed corpus
	f.Add(byte(0x01)) // CONNECT
	f.Add(byte(0x02)) // BIND
	f.Add(byte(0x03)) // UDP ASSOCIATE
	f.Add(byte(0x00))
	f.Add(byte(0xff))

	f.Fuzz(func(t *testing.T, cmd byte) {
		// Should not panic on any input
		_ = validation.ValidateSOCKS5Command(cmd)
	})
}

// FuzzValidateIPAddress tests IP address string validation with random inputs
func FuzzValidateIPAddress(f *testing.F) {
	// Seed corpus with valid and invalid IP addresses
	f.Add("192.168.1.1")
	f.Add("2001:db8::1")
	f.Add("invalid")
	f.Add("")
	f.Add("999.999.999.999")
	f.Add(":::")

	f.Fuzz(func(t *testing.T, addr string) {
		// Should not panic on any input
		_ = validation.ValidateIPAddress(addr)
	})
}

// FuzzValidatePort tests port validation with random inputs
func FuzzValidatePort(f *testing.F) {
	// Seed corpus
	f.Add(uint16(80))
	f.Add(uint16(443))
	f.Add(uint16(0))
	f.Add(uint16(65535))
	f.Add(uint16(1))

	f.Fuzz(func(t *testing.T, port uint16) {
		// Should not panic on any input
		_ = validation.ValidatePort(int(port))
	})
}
