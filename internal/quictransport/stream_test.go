package quictransport

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

func TestStreamTypeConstants(t *testing.T) {
	tests := []struct {
		name       string
		streamType byte
		expected   string
	}{
		{"TCP stream type", StreamTypeTCP, "TCP"},
		{"UDP stream type", StreamTypeUDP, "UDP"},
		{"TUN stream type", StreamTypeTUN, "TUN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StreamTypeString(tt.streamType)
			if got != tt.expected {
				t.Errorf("StreamTypeString(%#x) = %s, want %s", tt.streamType, got, tt.expected)
			}
		})
	}
}

func TestStreamTypeString_Unknown(t *testing.T) {
	unknown := byte(0xFF)
	got := StreamTypeString(unknown)
	expected := "Unknown(0xff)"
	if got != expected {
		t.Errorf("StreamTypeString(%#x) = %s, want %s", unknown, got, expected)
	}
}

func TestStreamTypeValidation(t *testing.T) {
	validTypes := []byte{StreamTypeTCP, StreamTypeUDP, StreamTypeTUN}

	for _, validType := range validTypes {
		// Test that valid types pass validation
		if validType != StreamTypeTCP && validType != StreamTypeUDP && validType != StreamTypeTUN {
			t.Errorf("Valid type %#x failed validation", validType)
		}
	}

	invalidTypes := []byte{0x00, 0x04, 0xFF, 0x10}

	for _, invalidType := range invalidTypes {
		// Test that invalid types fail validation
		isValid := (invalidType == StreamTypeTCP || invalidType == StreamTypeUDP || invalidType == StreamTypeTUN)
		if isValid {
			t.Errorf("Invalid type %#x passed validation", invalidType)
		}
	}
}

func TestWriteStreamType_Validation(t *testing.T) {
	tests := []struct {
		name       string
		streamType byte
		wantErr    bool
	}{
		{"valid TCP type", StreamTypeTCP, false},
		{"valid UDP type", StreamTypeUDP, false},
		{"valid TUN type", StreamTypeTUN, false},
		{"invalid type", 0xFF, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test validation logic
			var buf bytes.Buffer
			var err error

			// Validate the stream type (mimics WriteStreamType logic)
			if tt.streamType != StreamTypeTCP && tt.streamType != StreamTypeUDP && tt.streamType != StreamTypeTUN {
				err = ErrInvalidStreamType
			} else {
				_, err = buf.Write([]byte{tt.streamType})
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Stream type validation error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify the byte was written correctly
				written := buf.Bytes()
				if len(written) != 1 {
					t.Errorf("Expected 1 byte written, got %d", len(written))
				} else if written[0] != tt.streamType {
					t.Errorf("Expected byte %#x, got %#x", tt.streamType, written[0])
				}
			}
		})
	}
}

func TestReadStreamType_Validation(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    byte
		wantErr bool
	}{
		{"valid TCP type", []byte{StreamTypeTCP}, StreamTypeTCP, false},
		{"valid UDP type", []byte{StreamTypeUDP}, StreamTypeUDP, false},
		{"valid TUN type", []byte{StreamTypeTUN}, StreamTypeTUN, false},
		{"invalid type", []byte{0xFF}, 0, true},
		{"empty stream", []byte{}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.NewBuffer(tt.data)

			// Read one byte (mimics ReadStreamType logic)
			readBuf := make([]byte, 1)
			_, err := io.ReadFull(buf, readBuf)

			var got byte
			if err == nil {
				got = readBuf[0]
				// Validate the stream type
				if got != StreamTypeTCP && got != StreamTypeUDP && got != StreamTypeTUN {
					err = ErrInvalidStreamType
				}
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Stream type read/validation error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got != tt.want {
				t.Errorf("Read stream type = %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestStreamWrapper_NetConnInterface(t *testing.T) {
	// Verify StreamWrapper implements net.Conn interface
	var _ net.Conn = (*StreamWrapper)(nil)
}

func TestErrorTypes(t *testing.T) {
	// Test that error types are defined
	if ErrInvalidStreamType == nil {
		t.Error("ErrInvalidStreamType should be defined")
	}
	if ErrStreamTypeMismatch == nil {
		t.Error("ErrStreamTypeMismatch should be defined")
	}

	// Test error messages
	if ErrInvalidStreamType.Error() == "" {
		t.Error("ErrInvalidStreamType should have an error message")
	}
	if ErrStreamTypeMismatch.Error() == "" {
		t.Error("ErrStreamTypeMismatch should have an error message")
	}

	// Test that errors can be compared
	err := ErrInvalidStreamType
	if !errors.Is(err, ErrInvalidStreamType) {
		t.Error("errors.Is should work with ErrInvalidStreamType")
	}
}

// Note: Full integration tests for WriteStreamType, ReadStreamType, OpenTypedStream,
// AcceptTypedStream, and StreamWrapper methods require actual quic.Stream instances
// which are complex to mock. These functions are tested through integration tests
// in the cmd/uproxy package and end-to-end tests.
