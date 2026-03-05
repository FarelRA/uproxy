package uproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"log/slog"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"uproxy/internal/config"
)

// homeDirFunc is a variable for dependency injection in tests
var homeDirFunc = os.UserHomeDir

// cachedSSHDir caches the resolved SSH directory to avoid repeated lookups
var cachedSSHDir string

// resolveSSHDir resolves the SSH directory path.
// If sshDir is provided, it returns that directory.
// Otherwise, it returns ~/.ssh directory (cached after first lookup).
func resolveSSHDir(sshDir string) (string, error) {
	if sshDir != "" {
		return sshDir, nil
	}

	// Return cached value if available
	if cachedSSHDir != "" {
		return cachedSSHDir, nil
	}

	home, err := homeDirFunc()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	cachedSSHDir = filepath.Join(home, config.SSHDirName)
	return cachedSSHDir, nil
}

// LoadPrivateKey attempts to load the SSH client identity file.
// If privateKeyPath is specified, it loads that specific file.
// If sshDir is specified, it looks for id_ed25519 or id_rsa in that directory.
// Otherwise, it defaults to ~/.ssh directory.
func LoadPrivateKey(sshDir, privateKeyPath string) (ssh.Signer, error) {
	var paths []string

	// If specific private key path is provided, use only that
	if privateKeyPath != "" {
		paths = []string{privateKeyPath}
	} else {
		// Determine SSH directory
		dir, err := resolveSSHDir(sshDir)
		if err != nil {
			return nil, err
		}

		// Try common key names in order of preference
		paths = []string{
			filepath.Join(dir, config.SSHPrivateKeyEd25519),
			filepath.Join(dir, config.SSHPrivateKeyRSA),
		}
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
		if privateKeyPath != "" {
			return nil, fmt.Errorf("could not read private key from %s", privateKeyPath)
		}
		return nil, fmt.Errorf("could not find %s or %s in SSH directory.", config.SSHPrivateKeyEd25519, config.SSHPrivateKeyRSA)
	}

	signer, err := ssh.ParsePrivateKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key from %s: %w", loadedPath, err)
	}

	slog.Debug("Loaded client SSH private key", "path", loadedPath, "type", signer.PublicKey().Type())
	return signer, nil
}

// CheckAuthorizedKeys verifies if the incoming client's public key matches any entry
// in the server user's authorized_keys file.
// If authorizedKeysPath is specified, it uses that file.
// If sshDir is specified, it looks for authorized_keys in that directory.
// Otherwise, it defaults to ~/.ssh/authorized_keys.
func CheckAuthorizedKeys(pubKey ssh.PublicKey, sshDir, authorizedKeysPath string) error {
	authFile := authorizedKeysPath
	if authFile == "" {
		dir, err := resolveSSHDir(sshDir)
		if err != nil {
			return err
		}
		authFile = filepath.Join(dir, config.SSHAuthorizedKeysFile)
	}

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
			slog.Debug("Client public key matched authorized_keys entry", "type", pubKey.Type(), "file", authFile)
			return nil
		}
		b = rest
	}
	return fmt.Errorf("public key not found in authorized_keys (%s)", authFile)
}

// VerifyKnownHost acts as the client-side TOFU (Trust On First Use) mechanism.
// It strictly validates the server's host key against known_hosts file.
// If knownHostsPath is specified, it uses that file.
// If sshDir is specified, it looks for known_hosts in that directory.
// Otherwise, it defaults to ~/.ssh/known_hosts.
func VerifyKnownHost(address string, remote net.Addr, pubKey ssh.PublicKey, sshDir, knownHostsPath string) error {
	khPath := knownHostsPath
	if khPath == "" {
		dir, err := resolveSSHDir(sshDir)
		if err != nil {
			return err
		}
		khPath = filepath.Join(dir, config.SSHKnownHostsFile)
	}

	// Ensure known_hosts exists to prevent parsing panics
	if _, err := os.Stat(khPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(khPath), 0700); err == nil {
			_ = os.WriteFile(khPath, []byte(""), 0600)
		}
	}

	hostKeyCallback, err := knownhosts.New(khPath)
	if err == nil {
		err = hostKeyCallback(address, remote, pubKey)
		if err == nil {
			slog.Debug("Server host key verified successfully", "address", address, "file", khPath)
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
	return promptAndAddKnownHost(normalizedHost, pubKey, khPath)
}

// promptAndAddKnownHost pauses the background daemon to interactively ask the user
// if they want to trust a completely new proxy server.
// appendKnownHostEntry appends a host key entry to the known_hosts file
func appendKnownHostEntry(knownHostsPath, normalizedHost string, pubKey ssh.PublicKey) error {
	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts for writing: %w", err)
	}
	defer f.Close()

	line := knownhosts.Line([]string{normalizedHost}, pubKey)
	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("failed to append to known_hosts: %w", err)
	}

	return nil
}

func promptAndAddKnownHost(normalizedHost string, pubKey ssh.PublicKey, knownHostsPath string) error {
	// Attempt to bypass background detached streams by writing straight to the TTY
	tty, err := os.OpenFile(config.DevTTYPath, os.O_RDWR, 0)
	if err != nil {
		slog.Warn("Failed to open /dev/tty for interactive prompt, falling back to os.Stdin")
		tty = os.Stdin
	}
	if tty != os.Stdin {
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
		return errors.New("host key verification failed (user rejected).")
	}

	if err := appendKnownHostEntry(knownHostsPath, normalizedHost, pubKey); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Warning: Permanently added '%s' (%s) to the list of known hosts.\n", normalizedHost, pubKey.Type())
	return nil
}

// SSHSignerToTLSCertificate generates a self-signed X.509 certificate from an SSH signer.
// The certificate is valid for the specified duration and can include optional hostnames.
// This allows SSH keys to be used for TLS/QUIC authentication.
func SSHSignerToTLSCertificate(signer ssh.Signer, validFor time.Duration, hostnames []string) (tls.Certificate, error) {
	sshPubKey := signer.PublicKey()
	keyType := sshPubKey.Type()

	var privKey interface{}
	var pubKey interface{}

	switch keyType {
	case "ssh-ed25519":
		cryptoPub, ok := sshPubKey.(ssh.CryptoPublicKey)
		if !ok {
			return tls.Certificate{}, fmt.Errorf("failed to get crypto public key from SSH Ed25519 key")
		}
		ed25519Pub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			return tls.Certificate{}, fmt.Errorf("SSH key is not Ed25519")
		}

		cryptoSigner, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return tls.Certificate{}, fmt.Errorf("SSH signer does not implement AlgorithmSigner")
		}

		ed25519Priv, err := extractEd25519PrivateKey(cryptoSigner)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to extract Ed25519 private key: %w", err)
		}

		privKey = ed25519Priv
		pubKey = ed25519Pub

	case "ssh-rsa":
		cryptoPub, ok := sshPubKey.(ssh.CryptoPublicKey)
		if !ok {
			return tls.Certificate{}, fmt.Errorf("failed to get crypto public key from SSH RSA key")
		}
		rsaPub, ok := cryptoPub.CryptoPublicKey().(*rsa.PublicKey)
		if !ok {
			return tls.Certificate{}, fmt.Errorf("SSH key is not RSA")
		}

		cryptoSigner, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return tls.Certificate{}, fmt.Errorf("SSH signer does not implement AlgorithmSigner")
		}

		rsaPriv, err := extractRSAPrivateKey(cryptoSigner)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to extract RSA private key: %w", err)
		}

		privKey = rsaPriv
		pubKey = rsaPub

	default:
		return tls.Certificate{}, fmt.Errorf("unsupported SSH key type: %s (only ssh-ed25519 and ssh-rsa are supported)", keyType)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "uproxy",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              hostnames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}, nil
}

// extractEd25519PrivateKey extracts the Ed25519 private key from an SSH signer.
func extractEd25519PrivateKey(signer ssh.AlgorithmSigner) (ed25519.PrivateKey, error) {
	cryptoSigner, ok := signer.(interface{ CryptoPrivateKey() interface{} })
	if !ok {
		return nil, fmt.Errorf("signer does not expose CryptoPrivateKey method")
	}

	priv := cryptoSigner.CryptoPrivateKey()
	ed25519Priv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		ed25519PrivPtr, ok := priv.(*ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not Ed25519")
		}
		ed25519Priv = *ed25519PrivPtr
	}

	return ed25519Priv, nil
}

// extractRSAPrivateKey extracts the RSA private key from an SSH signer.
func extractRSAPrivateKey(signer ssh.AlgorithmSigner) (*rsa.PrivateKey, error) {
	cryptoSigner, ok := signer.(interface{ CryptoPrivateKey() interface{} })
	if !ok {
		return nil, fmt.Errorf("signer does not expose CryptoPrivateKey method")
	}

	priv := cryptoSigner.CryptoPrivateKey()
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	return rsaPriv, nil
}

// ExtractSSHPublicKeyFromCert extracts the SSH public key from an X.509 certificate.
// This allows comparing the certificate's public key against authorized_keys or known_hosts.
func ExtractSSHPublicKeyFromCert(cert *x509.Certificate) (ssh.PublicKey, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	if cert.PublicKey == nil {
		return nil, fmt.Errorf("certificate has no public key")
	}

	sshPubKey, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert certificate public key to SSH format: %w", err)
	}

	return sshPubKey, nil
}

// ParseRawCertificate parses a raw certificate byte slice into an x509.Certificate.
func ParseRawCertificate(rawCert []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// VerifyClientCertificate is a TLS verification callback for the server to verify client certificates.
// It extracts the SSH public key from the client's certificate and checks it against authorized_keys.
func VerifyClientCertificate(rawCerts [][]byte, sshDir, authorizedKeysPath string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	cert, err := ParseRawCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse client certificate: %w", err)
	}

	sshPubKey, err := ExtractSSHPublicKeyFromCert(cert)
	if err != nil {
		return fmt.Errorf("failed to extract SSH public key from client certificate: %w", err)
	}

	slog.Debug("Verifying client certificate", "key_type", sshPubKey.Type(), "fingerprint", ssh.FingerprintSHA256(sshPubKey))

	if err := CheckAuthorizedKeys(sshPubKey, sshDir, authorizedKeysPath); err != nil {
		return fmt.Errorf("client authentication failed: %w", err)
	}

	slog.Debug("Client certificate verified successfully", "key_type", sshPubKey.Type())
	return nil
}

// VerifyServerCertificate is a TLS verification callback for the client to verify server certificates.
// It extracts the SSH public key from the server's certificate and checks it against known_hosts.
// Implements TOFU (Trust On First Use) for unknown servers.
func VerifyServerCertificate(rawCerts [][]byte, serverAddr string, sshDir, knownHostsPath string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no server certificate provided")
	}

	cert, err := ParseRawCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %w", err)
	}

	sshPubKey, err := ExtractSSHPublicKeyFromCert(cert)
	if err != nil {
		return fmt.Errorf("failed to extract SSH public key from server certificate: %w", err)
	}

	slog.Debug("Verifying server certificate", "address", serverAddr, "key_type", sshPubKey.Type(), "fingerprint", ssh.FingerprintSHA256(sshPubKey))

	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}

	dummyRemoteAddr := &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	if err := VerifyKnownHost(host, dummyRemoteAddr, sshPubKey, sshDir, knownHostsPath); err != nil {
		return fmt.Errorf("server authentication failed: %w", err)
	}

	slog.Debug("Server certificate verified successfully", "address", serverAddr, "key_type", sshPubKey.Type())
	return nil
}
