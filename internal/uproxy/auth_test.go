package uproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Test helpers

func generateTestKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()

	// Generate ED25519 key pair
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	// Create SSH signer from private key
	sshPrivateKey, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	// Marshal to OpenSSH format
	privateKeyBytes, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	// Encode to PEM format
	pemBytes := pem.EncodeToMemory(privateKeyBytes)

	return sshPrivateKey, pemBytes
}

func createTempSSHDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

// TestLoadPrivateKey_ValidKey tests loading a valid private key
func TestLoadPrivateKey_ValidKey(t *testing.T) {
	sshDir := createTempSSHDir(t)
	_, privateKeyBytes := generateTestKey(t)

	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(keyPath, privateKeyBytes, 0600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}

	signer, err := LoadPrivateKey(sshDir, "")
	if err != nil {
		t.Errorf("LoadPrivateKey failed: %v", err)
	}
	if signer == nil {
		t.Error("expected non-nil signer")
	}
}

// TestLoadPrivateKey_SpecificPath tests loading from a specific path
func TestLoadPrivateKey_SpecificPath(t *testing.T) {
	sshDir := createTempSSHDir(t)
	_, privateKeyBytes := generateTestKey(t)

	customPath := filepath.Join(sshDir, "custom_key")
	if err := os.WriteFile(customPath, privateKeyBytes, 0600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}

	signer, err := LoadPrivateKey("", customPath)
	if err != nil {
		t.Errorf("LoadPrivateKey with specific path failed: %v", err)
	}
	if signer == nil {
		t.Error("expected non-nil signer")
	}
}

// TestLoadPrivateKey_MissingKey tests behavior when key is missing
func TestLoadPrivateKey_MissingKey(t *testing.T) {
	sshDir := createTempSSHDir(t)

	_, err := LoadPrivateKey(sshDir, "")
	if err == nil {
		t.Error("expected error for missing key, got nil")
	}
}

// TestLoadPrivateKey_InvalidKey tests behavior with invalid key data
func TestLoadPrivateKey_InvalidKey(t *testing.T) {
	sshDir := createTempSSHDir(t)

	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("invalid key data"), 0600); err != nil {
		t.Fatalf("failed to write test key: %v", err)
	}

	_, err := LoadPrivateKey(sshDir, "")
	if err == nil {
		t.Error("expected error for invalid key, got nil")
	}
}

// TestLoadPrivateKey_PreferenceOrder tests that id_ed25519 is preferred over id_rsa
func TestLoadPrivateKey_PreferenceOrder(t *testing.T) {
	sshDir := createTempSSHDir(t)

	// Create both keys
	signer1, key1Bytes := generateTestKey(t)
	_, key2Bytes := generateTestKey(t)

	// Write id_rsa first
	rsaPath := filepath.Join(sshDir, "id_rsa")
	if err := os.WriteFile(rsaPath, key2Bytes, 0600); err != nil {
		t.Fatalf("failed to write id_rsa: %v", err)
	}

	// Write id_ed25519 second
	ed25519Path := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(ed25519Path, key1Bytes, 0600); err != nil {
		t.Fatalf("failed to write id_ed25519: %v", err)
	}

	signer, err := LoadPrivateKey(sshDir, "")
	if err != nil {
		t.Fatalf("LoadPrivateKey failed: %v", err)
	}

	// Should load id_ed25519 (first in preference order)
	if string(signer.PublicKey().Marshal()) != string(signer1.PublicKey().Marshal()) {
		t.Error("expected id_ed25519 to be loaded, but got different key")
	}
}

// TestCheckAuthorizedKeys_Authorized tests successful authorization
func TestCheckAuthorizedKeys_Authorized(t *testing.T) {
	sshDir := createTempSSHDir(t)
	signer, _ := generateTestKey(t)

	// Write authorized_keys
	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	authKeyLine := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	if err := os.WriteFile(authKeysPath, []byte(authKeyLine), 0600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	err := CheckAuthorizedKeys(signer.PublicKey(), sshDir, "")
	if err != nil {
		t.Errorf("CheckAuthorizedKeys failed: %v", err)
	}
}

// TestCheckAuthorizedKeys_Unauthorized tests failed authorization
func TestCheckAuthorizedKeys_Unauthorized(t *testing.T) {
	sshDir := createTempSSHDir(t)
	signer1, _ := generateTestKey(t)
	signer2, _ := generateTestKey(t)

	// Write authorized_keys with different key
	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	authKeyLine := string(ssh.MarshalAuthorizedKey(signer1.PublicKey()))
	if err := os.WriteFile(authKeysPath, []byte(authKeyLine), 0600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	// Try to authorize with different key
	err := CheckAuthorizedKeys(signer2.PublicKey(), sshDir, "")
	if err == nil {
		t.Error("expected error for unauthorized key, got nil")
	}
}

// TestCheckAuthorizedKeys_MissingFile tests behavior when authorized_keys is missing
func TestCheckAuthorizedKeys_MissingFile(t *testing.T) {
	sshDir := createTempSSHDir(t)
	signer, _ := generateTestKey(t)

	err := CheckAuthorizedKeys(signer.PublicKey(), sshDir, "")
	if err == nil {
		t.Error("expected error for missing authorized_keys, got nil")
	}
}

// TestCheckAuthorizedKeys_MultipleKeys tests authorization with multiple keys in file
func TestCheckAuthorizedKeys_MultipleKeys(t *testing.T) {
	sshDir := createTempSSHDir(t)
	signer1, _ := generateTestKey(t)
	signer2, _ := generateTestKey(t)
	signer3, _ := generateTestKey(t)

	// Write authorized_keys with multiple keys
	authKeysPath := filepath.Join(sshDir, "authorized_keys")
	content := string(ssh.MarshalAuthorizedKey(signer1.PublicKey())) +
		string(ssh.MarshalAuthorizedKey(signer2.PublicKey())) +
		string(ssh.MarshalAuthorizedKey(signer3.PublicKey()))
	if err := os.WriteFile(authKeysPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	// Should find signer2 in the middle
	err := CheckAuthorizedKeys(signer2.PublicKey(), sshDir, "")
	if err != nil {
		t.Errorf("CheckAuthorizedKeys failed for key in middle: %v", err)
	}
}

// TestCheckAuthorizedKeys_SpecificPath tests using a specific authorized_keys path
func TestCheckAuthorizedKeys_SpecificPath(t *testing.T) {
	sshDir := createTempSSHDir(t)
	signer, _ := generateTestKey(t)

	customPath := filepath.Join(sshDir, "custom_authorized_keys")
	authKeyLine := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	if err := os.WriteFile(customPath, []byte(authKeyLine), 0600); err != nil {
		t.Fatalf("failed to write custom authorized_keys: %v", err)
	}

	err := CheckAuthorizedKeys(signer.PublicKey(), "", customPath)
	if err != nil {
		t.Errorf("CheckAuthorizedKeys with custom path failed: %v", err)
	}
}

// TestVerifyKnownHost_KnownHost tests verification of a known host
func TestVerifyKnownHost_KnownHost(t *testing.T) {
	sshDir := createTempSSHDir(t)
	signer, _ := generateTestKey(t)

	// Create known_hosts with the host in proper format
	knownHostsPath := filepath.Join(sshDir, "known_hosts")
	addr := "example.com:22"

	// Use knownhosts.Line to generate proper format
	line := ssh.MarshalAuthorizedKey(signer.PublicKey())
	knownHostLine := fmt.Sprintf("%s %s", addr, string(line))
	if err := os.WriteFile(knownHostsPath, []byte(knownHostLine), 0600); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	remoteAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	err := VerifyKnownHost(addr, remoteAddr, signer.PublicKey(), sshDir, "")
	if err != nil {
		t.Errorf("VerifyKnownHost failed for known host: %v", err)
	}
}

// TestVerifyKnownHost_ChangedHost tests detection of changed host key
func TestVerifyKnownHost_ChangedHost(t *testing.T) {
	sshDir := createTempSSHDir(t)
	signer1, _ := generateTestKey(t)
	signer2, _ := generateTestKey(t)

	// Create known_hosts with first key in proper format
	knownHostsPath := filepath.Join(sshDir, "known_hosts")
	addr := "example.com:22"
	line := ssh.MarshalAuthorizedKey(signer1.PublicKey())
	knownHostLine := fmt.Sprintf("%s %s", addr, string(line))
	if err := os.WriteFile(knownHostsPath, []byte(knownHostLine), 0600); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	// Try to verify with different key
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	err := VerifyKnownHost(addr, remoteAddr, signer2.PublicKey(), sshDir, "")
	if err == nil {
		t.Error("expected error for changed host key, got nil")
	}

	// Should contain warning about changed host
	if err != nil && !contains(err.Error(), "CHANGED") {
		t.Errorf("expected CHANGED warning in error, got: %v", err)
	}
}

// TestVerifyKnownHost_EmptyFile tests behavior with empty known_hosts
func TestVerifyKnownHost_EmptyFile(t *testing.T) {
	sshDir := createTempSSHDir(t)
	signer, _ := generateTestKey(t)

	// Create empty known_hosts
	knownHostsPath := filepath.Join(sshDir, "known_hosts")
	if err := os.WriteFile(knownHostsPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	remoteAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	err := VerifyKnownHost("example.com:22", remoteAddr, signer.PublicKey(), sshDir, "")

	// Should fail because we can't interactively prompt in tests
	if err == nil {
		t.Error("expected error for unknown host (no interactive prompt), got nil")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
