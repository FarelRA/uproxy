package uproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func generateTestKey(t *testing.T, keyType string) (ssh.Signer, []byte) {
	t.Helper()

	if keyType == "ed25519" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("failed to create signer: %v", err)
		}
		pemBytes := ssh.MarshalAuthorizedKey(signer.PublicKey())
		return signer, pemBytes
	}

	// RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	pemBytes := ssh.MarshalAuthorizedKey(signer.PublicKey())
	return signer, pemBytes
}

func generateTestPrivateKey(t *testing.T, keyType string) (ssh.Signer, []byte) {
	t.Helper()

	if keyType == "ed25519" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ed25519 key: %v", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("failed to create signer: %v", err)
		}
		pemBlock, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			t.Fatalf("failed to marshal private key: %v", err)
		}
		pemBytes := pem.EncodeToMemory(pemBlock)
		return signer, pemBytes
	}

	// RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	return signer, pemBytes
}

func TestLoadPrivateKey_SpecificPath(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key")

	_, privKeyBytes := generateTestPrivateKey(t, "ed25519")

	if err := os.WriteFile(keyPath, privKeyBytes, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	signer, _, err := LoadPrivateKey("", keyPath)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if signer == nil {
		t.Error("expected signer, got nil")
	}
}

func TestLoadPrivateKey_SpecificPathInvalidFormat(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_key")

	signer, _ := generateTestKey(t, "ed25519")
	keyBytes := ssh.MarshalAuthorizedKey(signer.PublicKey())

	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	_, _, err := LoadPrivateKey("", keyPath)
	if err == nil {
		t.Error("expected error parsing invalid key format, got nil")
	}
}

func TestLoadPrivateKey_SpecificPathNotFound(t *testing.T) {
	_, _, err := LoadPrivateKey("", "/nonexistent/key")
	if err == nil {
		t.Error("expected error for nonexistent key, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "no valid private key found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadPrivateKey_SSHDir(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_ed25519")

	_, privKeyBytes := generateTestPrivateKey(t, "ed25519")

	if err := os.WriteFile(keyPath, privKeyBytes, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	signer, _, err := LoadPrivateKey(tmpDir, "")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if signer == nil {
		t.Error("expected signer, got nil")
	}
}

func TestLoadPrivateKey_NoKeysFound(t *testing.T) {
	tmpDir := t.TempDir()

	_, _, err := LoadPrivateKey(tmpDir, "")
	if err == nil {
		t.Error("expected error when no keys found, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "no valid private key found") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadPrivateKey_RSAFallback(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "id_rsa")

	_, privKeyBytes := generateTestPrivateKey(t, "rsa")

	if err := os.WriteFile(keyPath, privKeyBytes, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	signer, _, err := LoadPrivateKey(tmpDir, "")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if signer == nil {
		t.Error("expected signer, got nil")
	}
	if signer.PublicKey().Type() != "ssh-rsa" {
		t.Errorf("expected RSA key, got: %s", signer.PublicKey().Type())
	}
}

func TestCheckAuthorizedKeys_Match(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "authorized_keys")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()
	authLine := string(ssh.MarshalAuthorizedKey(pubKey))

	if err := os.WriteFile(authFile, []byte(authLine), 0600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	err := CheckAuthorizedKeys(pubKey, "", authFile)
	if err != nil {
		t.Errorf("expected no error for matching key, got: %v", err)
	}
}

func TestCheckAuthorizedKeys_NoMatch(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "authorized_keys")

	signer1, _ := generateTestKey(t, "ed25519")
	signer2, _ := generateTestKey(t, "ed25519")

	authLine := string(ssh.MarshalAuthorizedKey(signer1.PublicKey()))

	if err := os.WriteFile(authFile, []byte(authLine), 0600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	err := CheckAuthorizedKeys(signer2.PublicKey(), "", authFile)
	if err == nil {
		t.Error("expected error for non-matching key, got nil")
	}
}

func TestCheckAuthorizedKeys_FileNotFound(t *testing.T) {
	signer, _ := generateTestKey(t, "ed25519")

	err := CheckAuthorizedKeys(signer.PublicKey(), "", "/nonexistent/authorized_keys")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestCheckAuthorizedKeys_SSHDir(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "authorized_keys")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()
	authLine := string(ssh.MarshalAuthorizedKey(pubKey))

	if err := os.WriteFile(authFile, []byte(authLine), 0600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	err := CheckAuthorizedKeys(pubKey, tmpDir, "")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestCheckAuthorizedKeys_InvalidLines(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "authorized_keys")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	content := "invalid line\n" + string(ssh.MarshalAuthorizedKey(pubKey))

	if err := os.WriteFile(authFile, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	err := CheckAuthorizedKeys(pubKey, "", authFile)
	if err != nil {
		t.Errorf("expected no error (should skip invalid lines), got: %v", err)
	}
}

func TestVerifyKnownHost_KnownHost(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	line := knownhosts.Line([]string{"example.com:22"}, pubKey)
	if err := os.WriteFile(khPath, []byte(line+"\n"), 0600); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	err := VerifyKnownHost("example.com:22", addr, pubKey, "", khPath)
	if err != nil {
		t.Errorf("expected no error for known host, got: %v", err)
	}
}

func TestVerifyKnownHost_ChangedKey(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	signer1, _ := generateTestKey(t, "ed25519")
	signer2, _ := generateTestKey(t, "ed25519")

	line := knownhosts.Line([]string{"example.com:22"}, signer1.PublicKey())
	if err := os.WriteFile(khPath, []byte(line+"\n"), 0600); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	err := VerifyKnownHost("example.com:22", addr, signer2.PublicKey(), "", khPath)
	if err == nil {
		t.Error("expected error for changed host key, got nil")
	}
}

func TestVerifyKnownHost_SSHDir(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	line := knownhosts.Line([]string{"example.com:22"}, pubKey)
	if err := os.WriteFile(khPath, []byte(line+"\n"), 0600); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	err := VerifyKnownHost("example.com:22", addr, pubKey, tmpDir, "")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestVerifyKnownHost_CreatesFile(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "subdir", "known_hosts")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	err := VerifyKnownHost("example.com:22", addr, pubKey, "", khPath)

	// This will fail because it tries to prompt, but the file should be created
	if _, statErr := os.Stat(khPath); statErr != nil {
		t.Errorf("expected known_hosts file to be created, got error: %v", statErr)
	}

	// Error is expected because we can't prompt in tests
	if err == nil {
		t.Error("expected error (can't prompt in test), got nil")
	}
}

func TestVerifyKnownHost_UserHomeDirError(t *testing.T) {
	// Mock homeDirFunc to return error
	originalHomeDir := homeDirFunc
	defer func() { homeDirFunc = originalHomeDir }()
	homeDirFunc = func() (string, error) {
		return "", fmt.Errorf("mock home dir error")
	}

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	err := VerifyKnownHost("example.com:22", addr, pubKey, "", "")
	if err == nil || !strings.Contains(err.Error(), "failed to get user home directory") {
		t.Errorf("expected UserHomeDir error, got: %v", err)
	}
}

func TestPromptAndAddKnownHost_NoTTY(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	// Close stdin to simulate no input
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Close()
	defer func() { os.Stdin = oldStdin }()

	err := promptAndAddKnownHost("example.com:22", pubKey, khPath)
	if err == nil {
		t.Error("expected error when no input available, got nil")
	}
}

func TestPromptAndAddKnownHost_UserRejects(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	// Simulate user typing "no"
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	fmt.Fprintln(w, "no")
	w.Close()
	defer func() { os.Stdin = oldStdin }()

	err := promptAndAddKnownHost("example.com:22", pubKey, khPath)
	if err == nil {
		t.Error("expected error when user rejects, got nil")
	}
	if err != nil && err.Error() != "host key verification failed (user rejected)." {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCheckAuthorizedKeys_UserHomeDirError(t *testing.T) {
	signer, _ := generateTestKey(t, "ed25519")

	// Mock homeDirFunc to return error
	oldHomeDir := homeDirFunc
	homeDirFunc = func() (string, error) {
		return "", fmt.Errorf("mock home dir error")
	}
	defer func() { homeDirFunc = oldHomeDir }()

	err := CheckAuthorizedKeys(signer.PublicKey(), "", "")
	if err == nil {
		t.Error("expected error when UserHomeDir fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get user home directory") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPromptAndAddKnownHost_UserAccepts(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	// Simulate user typing "yes"
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	fmt.Fprintln(w, "yes")
	w.Close()
	defer func() { os.Stdin = oldStdin }()

	err := promptAndAddKnownHost("example.com:22", pubKey, khPath)
	if err != nil {
		t.Errorf("expected no error when user accepts, got: %v", err)
	}

	// Verify the file was written
	content, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("failed to read known_hosts: %v", err)
	}
	if len(content) == 0 {
		t.Error("expected known_hosts to contain data")
	}
}

func TestCheckAuthorizedKeys_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "authorized_keys")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	// Create empty file
	if err := os.WriteFile(authFile, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	err := CheckAuthorizedKeys(pubKey, "", authFile)
	if err == nil {
		t.Error("expected error for empty file, got nil")
	}
}

func TestCheckAuthorizedKeys_OnlyComments(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := filepath.Join(tmpDir, "authorized_keys")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	// Create file with only comments
	content := "# comment line\n# another comment\n"
	if err := os.WriteFile(authFile, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	err := CheckAuthorizedKeys(pubKey, "", authFile)
	if err == nil {
		t.Error("expected error when no valid keys found, got nil")
	}
}

func TestVerifyKnownHost_FileReadError(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	// Create file with invalid permissions (write-only)
	if err := os.WriteFile(khPath, []byte("invalid"), 0200); err != nil {
		t.Fatalf("failed to write known_hosts: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	err := VerifyKnownHost("example.com:22", addr, pubKey, "", khPath)
	if err == nil {
		t.Error("expected error reading unreadable file, got nil")
	}

	// Clean up
	os.Chmod(khPath, 0600)
}

func TestPromptAndAddKnownHost_InvalidInput(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	// Simulate user typing invalid input then "no"
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	fmt.Fprintln(w, "maybe")
	fmt.Fprintln(w, "no")
	w.Close()
	defer func() { os.Stdin = oldStdin }()

	err := promptAndAddKnownHost("example.com:22", pubKey, khPath)
	if err == nil {
		t.Error("expected error when user rejects, got nil")
	}
}

func TestLoadPrivateKey_HomeDirError(t *testing.T) {
	// Mock homeDirFunc to return an error
	oldHomeDir := homeDirFunc
	homeDirFunc = func() (string, error) {
		return "", fmt.Errorf("mock home dir error")
	}
	defer func() { homeDirFunc = oldHomeDir }()

	_, _, err := LoadPrivateKey("", "")
	if err == nil {
		t.Error("expected error when homeDirFunc fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get user home directory") {
		t.Errorf("expected home directory error, got: %v", err)
	}
}

func TestCheckAuthorizedKeys_HomeDirError(t *testing.T) {
	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	// Mock homeDirFunc to return an error
	oldHomeDir := homeDirFunc
	homeDirFunc = func() (string, error) {
		return "", fmt.Errorf("mock home dir error")
	}
	defer func() { homeDirFunc = oldHomeDir }()

	err := CheckAuthorizedKeys(pubKey, "", "")
	if err == nil {
		t.Error("expected error when homeDirFunc fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get user home directory") {
		t.Errorf("expected home directory error, got: %v", err)
	}
}

func TestVerifyKnownHost_HomeDirError(t *testing.T) {
	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	// Mock homeDirFunc to return an error
	oldHomeDir := homeDirFunc
	homeDirFunc = func() (string, error) {
		return "", fmt.Errorf("mock home dir error")
	}
	defer func() { homeDirFunc = oldHomeDir }()

	err := VerifyKnownHost("example.com:22", addr, pubKey, "", "")
	if err == nil {
		t.Error("expected error when homeDirFunc fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get user home directory") {
		t.Errorf("expected home directory error, got: %v", err)
	}
}

func TestPromptAndAddKnownHost_WriteError(t *testing.T) {
	// Try to write to a directory that doesn't exist and can't be created
	khPath := "/proc/known_hosts_test_invalid"

	signer, _ := generateTestKey(t, "ed25519")
	pubKey := signer.PublicKey()

	// Simulate user typing "yes"
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	fmt.Fprintln(w, "yes")
	w.Close()
	defer func() { os.Stdin = oldStdin }()

	err := promptAndAddKnownHost("example.com:22", pubKey, khPath)
	if err == nil {
		t.Error("expected error writing to invalid path, got nil")
	}
}
