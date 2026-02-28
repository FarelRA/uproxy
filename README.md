# UDP "uninterruptable" QUIC proxy

This is an optimized TCP-over-UDP tunnel using QUIC (via `quic-go`).

It features 100% resilient UDP socket wrapping so you can seamlessly roam across networks (e.g., dropping WiFi for cellular) without your multiplexed TCP connections dying.

## Build

You need Go 1.24+

```bash
mkdir -p bin
GOOS=linux GOARCH=amd64 go build -o bin/udpproxy-server-linux-amd64 ./cmd/udpproxy-server
GOOS=linux GOARCH=amd64 go build -o bin/udpproxy-client-linux-amd64 ./cmd/udpproxy-client
```

## Run

### Setup Authentication

The system uses standard SSH-style mutual authentication (TOFU).

**On the client:**
1. Generate an SSH key if you don't have one: `ssh-keygen -t ed25519`
2. Copy your public key `~/.ssh/id_ed25519.pub` to the server's `~/.ssh/authorized_keys`.

**On the server:**
1. Generate an SSH key if you don't have one: `ssh-keygen -t ed25519`
2. Start the server (it will generate an ephemeral TLS cert signed by this key):
   ```bash
   ./udpproxy-server --udp-listen :6000
   ```

### Connect the Client

```bash
# SOCKS5 Dynamic Forwarding
./udpproxy-client --listen 127.0.0.1:1080 --udp-server server.example.com:6000
```

When you connect for the first time, it will prompt you to verify the server's public key fingerprint (just like SSH) and save it to `~/.ssh/known_hosts`.

If your network drops briefly or your IP changes, traffic pauses and resumes when UDP connectivity returns (default QUIC idle timeout is 1 hour).

## Features

- **SSH-like TOFU (Trust On First Use):** Uses `~/.ssh/id_ed25519` or `~/.ssh/id_rsa` for mutual authentication and `~/.ssh/known_hosts` for server pinning.
- **SOCKS5 Server:** The client natively acts as a SOCKS5 proxy (`--listen 127.0.0.1:1080`). All traffic dynamically routes via the server.
- **Extreme Performance:** Aggressive 7MB kernel UDP socket buffers and disabled Nagle's algorithm (TCP_NODELAY) with zero-copy stream memory pooling (`sync.Pool`).
