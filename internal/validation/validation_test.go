package validation

import (
	"testing"

	"uproxy/internal/config"
)

func TestValidateIPv4Packet(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{
			name: "valid IPv4 packet",
			packet: []byte{
				0x45, 0x00, 0x00, 0x14, // Version 4, IHL 5, TOS, Total Length 20
				0x00, 0x01, 0x00, 0x00, // ID, Flags, Fragment Offset
				0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum
				0xc0, 0xa8, 0x01, 0x01, // Source IP
				0xc0, 0xa8, 0x01, 0x02, // Dest IP
			},
			want: true,
		},
		{
			name:   "packet too short",
			packet: []byte{0x45, 0x00, 0x00},
			want:   false,
		},
		{
			name:   "empty packet",
			packet: []byte{},
			want:   false,
		},
		{
			name: "invalid IHL (less than 5)",
			packet: []byte{
				0x44, 0x00, 0x00, 0x28, // IHL = 4 (invalid)
				0x00, 0x01, 0x00, 0x00,
				0x40, 0x06, 0x00, 0x00,
				0xc0, 0xa8, 0x01, 0x01,
				0xc0, 0xa8, 0x01, 0x02,
			},
			want: false,
		},
		{
			name: "packet shorter than header length",
			packet: []byte{
				0x46, 0x00, 0x00, 0x28, // IHL = 6 (24 bytes header)
				0x00, 0x01, 0x00, 0x00,
				0x40, 0x06, 0x00, 0x00,
				0xc0, 0xa8, 0x01, 0x01,
				0xc0, 0xa8, 0x01, 0x02, // Only 20 bytes
			},
			want: false,
		},
		{
			name: "total length less than header length",
			packet: []byte{
				0x45, 0x00, 0x00, 0x10, // Total length = 16, but header is 20
				0x00, 0x01, 0x00, 0x00,
				0x40, 0x06, 0x00, 0x00,
				0xc0, 0xa8, 0x01, 0x01,
				0xc0, 0xa8, 0x01, 0x02,
			},
			want: false,
		},
		{
			name: "total length greater than packet length",
			packet: []byte{
				0x45, 0x00, 0x00, 0xFF, // Total length = 255
				0x00, 0x01, 0x00, 0x00,
				0x40, 0x06, 0x00, 0x00,
				0xc0, 0xa8, 0x01, 0x01,
				0xc0, 0xa8, 0x01, 0x02, // Only 20 bytes
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateIPv4Packet(tt.packet); got != tt.want {
				t.Errorf("ValidateIPv4Packet() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateIPv6Packet(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{
			name: "valid IPv6 packet",
			packet: func() []byte {
				p := make([]byte, 40)
				p[0] = 0x60 // Version 6
				p[4] = 0x00 // Payload length high byte
				p[5] = 0x00 // Payload length low byte
				return p
			}(),
			want: true,
		},
		{
			name: "valid IPv6 packet with payload",
			packet: func() []byte {
				p := make([]byte, 60)
				p[0] = 0x60 // Version 6
				p[4] = 0x00 // Payload length high byte
				p[5] = 0x14 // Payload length low byte (20 bytes)
				return p
			}(),
			want: true,
		},
		{
			name:   "packet too short",
			packet: []byte{0x60, 0x00, 0x00, 0x00},
			want:   false,
		},
		{
			name:   "empty packet",
			packet: []byte{},
			want:   false,
		},
		{
			name: "payload length exceeds packet",
			packet: func() []byte {
				p := make([]byte, 40)
				p[0] = 0x60 // Version 6
				p[4] = 0x00 // Payload length high byte
				p[5] = 0xFF // Payload length low byte (255 bytes)
				return p
			}(),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateIPv6Packet(tt.packet); got != tt.want {
				t.Errorf("ValidateIPv6Packet() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateIPPacket(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{
			name: "valid IPv4 packet",
			packet: []byte{
				0x45, 0x00, 0x00, 0x14, // Total Length 20
				0x00, 0x01, 0x00, 0x00,
				0x40, 0x06, 0x00, 0x00,
				0xc0, 0xa8, 0x01, 0x01,
				0xc0, 0xa8, 0x01, 0x02,
			},
			want: true,
		},
		{
			name: "valid IPv6 packet",
			packet: func() []byte {
				p := make([]byte, 40)
				p[0] = 0x60
				return p
			}(),
			want: true,
		},
		{
			name:   "empty packet",
			packet: []byte{},
			want:   false,
		},
		{
			name: "invalid version (3)",
			packet: []byte{
				0x35, 0x00, 0x00, 0x28, // Version 3
				0x00, 0x01, 0x00, 0x00,
			},
			want: false,
		},
		{
			name: "invalid version (7)",
			packet: []byte{
				0x75, 0x00, 0x00, 0x28, // Version 7
				0x00, 0x01, 0x00, 0x00,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateIPPacket(tt.packet); got != tt.want {
				t.Errorf("ValidateIPPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateSOCKS5Version(t *testing.T) {
	tests := []struct {
		name    string
		version byte
		want    bool
	}{
		{"valid version 5", 0x05, true},
		{"invalid version 4", 0x04, false},
		{"invalid version 0", 0x00, false},
		{"invalid version 6", 0x06, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateSOCKS5Version(tt.version); got != tt.want {
				t.Errorf("ValidateSOCKS5Version() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateSOCKS5AddressType(t *testing.T) {
	tests := []struct {
		name string
		atyp byte
		want bool
	}{
		{"IPv4 address type", 0x01, true},
		{"domain name type", 0x03, true},
		{"IPv6 address type", 0x04, true},
		{"invalid type 0", 0x00, false},
		{"invalid type 2", 0x02, false},
		{"invalid type 5", 0x05, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateSOCKS5AddressType(tt.atyp); got != tt.want {
				t.Errorf("ValidateSOCKS5AddressType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateSOCKS5Command(t *testing.T) {
	tests := []struct {
		name string
		cmd  byte
		want bool
	}{
		{"CONNECT command", 0x01, true},
		{"BIND command", 0x02, true},
		{"UDP ASSOCIATE command", 0x03, true},
		{"invalid command 0", 0x00, false},
		{"invalid command 4", 0x04, false},
		{"invalid command 255", 0xFF, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateSOCKS5Command(tt.cmd); got != tt.want {
				t.Errorf("ValidateSOCKS5Command() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateClientMode(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.ClientConfig
		wantErr bool
	}{
		{
			name: "valid socks5 mode with listen",
			cfg: &config.ClientConfig{
				Mode:       "socks5",
				ListenAddr: "127.0.0.1:1080",
			},
			wantErr: false,
		},
		{
			name: "socks5 mode without listen",
			cfg: &config.ClientConfig{
				Mode:       "socks5",
				ListenAddr: "",
			},
			wantErr: true,
		},
		{
			name: "auto mode",
			cfg: &config.ClientConfig{
				Mode: "auto",
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			cfg: &config.ClientConfig{
				Mode: "invalid",
			},
			wantErr: true,
		},
		{
			name: "tun mode",
			cfg: &config.ClientConfig{
				Mode: "tun",
			},
			wantErr: false, // Privilege check happens at runtime, not during validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientMode(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateClientMode() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{"valid IPv4", "192.168.1.1", true},
		{"valid IPv4 loopback", "127.0.0.1", true},
		{"valid IPv6", "2001:db8::1", true},
		{"valid IPv6 loopback", "::1", true},
		{"invalid IP", "not.an.ip", false},
		{"invalid IP format", "256.256.256.256", false},
		{"empty string", "", false},
		{"partial IP", "192.168", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateIPAddress(tt.addr); got != tt.want {
				t.Errorf("ValidateIPAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name string
		port int
		want bool
	}{
		{"valid port 80", 80, true},
		{"valid port 1", 1, true},
		{"valid port 65535", 65535, true},
		{"valid port 8080", 8080, true},
		{"invalid port 0", 0, false},
		{"invalid port -1", -1, false},
		{"invalid port 65536", 65536, false},
		{"invalid port 100000", 100000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidatePort(tt.port); got != tt.want {
				t.Errorf("ValidatePort() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
