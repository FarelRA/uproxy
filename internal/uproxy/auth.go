package uproxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"log/slog"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// LoadPrivateKey attempts to load the SSH client identity file.
// It prioritizes id_ed25519, falling back to id_rsa if necessary.
func LoadPrivateKey() (ssh.Signer, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	paths := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}

	var rawKey []byte
	var loadedPath string
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			rawKey = b
			loadedPath = p
			break
		}
	}
	if rawKey == nil {
		return nil, errors.New("could not find id_ed25519 or id_rsa in ~/.ssh")
	}

	signer, err := ssh.ParsePrivateKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key from %s: %w", loadedPath, err)
	}

	slog.Debug("Loaded client SSH private key", "path", loadedPath, "type", signer.PublicKey().Type())
	return signer, nil
}

// CheckAuthorizedKeys verifies if the incoming client's public key matches any entry
// in the server user's ~/.ssh/authorized_keys file.
func CheckAuthorizedKeys(pubKey ssh.PublicKey) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}

	authFile := filepath.Join(home, ".ssh", "authorized_keys")
	b, err := os.ReadFile(authFile)
	if err != nil {
		return fmt.Errorf("could not read authorized_keys at %s: %w", authFile, err)
	}

	for len(b) > 0 {
		pub, _, _, rest, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			b = rest
			continue
		}
		if string(pub.Marshal()) == string(pubKey.Marshal()) {
			slog.Debug("Client public key matched authorized_keys entry", "type", pubKey.Type())
			return nil
		}
		b = rest
	}
	return errors.New("public key not found in authorized_keys")
}

// VerifyKnownHost acts as the client-side TOFU (Trust On First Use) mechanism.
// It strictly validates the server's host key against ~/.ssh/known_hosts.
func VerifyKnownHost(address string, remote net.Addr, pubKey ssh.PublicKey) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")

	// Ensure known_hosts exists to prevent parsing panics
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0700); err == nil {
			_ = os.WriteFile(knownHostsPath, []byte(""), 0600)
		}
	}

	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err == nil {
		err = hostKeyCallback(address, remote, pubKey)
		if err == nil {
			slog.Debug("Server host key verified successfully", "address", address)
			return nil // Server is strictly trusted
		}

		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) > 0 {
				return fmt.Errorf("\n"+
					"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"+
					"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"+
					"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"+
					"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n"+
					"Host key for %s has changed. Expected %s, got %s", address, keyErr.Want[0].Key.Type(), pubKey.Type())
			}
			// Host is completely unknown, fallthrough to TOFU prompt
		} else {
			return fmt.Errorf("host key callback error: %w", err)
		}
	}

	normalizedHost := knownhosts.Normalize(address)
	return promptAndAddKnownHost(normalizedHost, pubKey, knownHostsPath)
}

// promptAndAddKnownHost pauses the background daemon to interactively ask the user
// if they want to trust a completely new proxy server.
func promptAndAddKnownHost(normalizedHost string, pubKey ssh.PublicKey, knownHostsPath string) error {
	// Attempt to bypass background detached streams by writing straight to the TTY
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		slog.Warn("Failed to open /dev/tty for interactive prompt, falling back to os.Stdin")
		tty = os.Stdin
	} else {
		defer tty.Close()
	}

	fmt.Fprintf(os.Stderr, "The authenticity of host '%s' can't be established.\n", normalizedHost)
	fmt.Fprintf(os.Stderr, "%s key fingerprint is %s.\n", pubKey.Type(), ssh.FingerprintSHA256(pubKey))
	fmt.Fprintf(os.Stderr, "Are you sure you want to continue connecting (yes/no)? ")

	var response string
	if _, err := fmt.Fscanln(tty, &response); err != nil {
		return errors.New("aborted by user (no tty/stdin input)")
	}

	response = strings.ToLower(strings.TrimSpace(response))
	if response != "yes" {
		return errors.New("host key verification failed (user rejected)")
	}

	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts for writing: %w", err)
	}
	defer f.Close()

	line := knownhosts.Line([]string{normalizedHost}, pubKey)
	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("failed to append to known_hosts: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Warning: Permanently added '%s' (%s) to the list of known hosts.\n", normalizedHost, pubKey.Type())
	return nil
}
