# uproxy (The Uninterruptible Proxy)

**uproxy** is a highly optimized, cryptographically secure, and completely uninterruptible SOCKS5 proxy. 

It is designed for one specific purpose: **to keep your connections alive no matter what happens to your physical network.** Whether you are switching from Wi-Fi to Cellular, driving through a tunnel, or closing your laptop lid for a 1-hour flight, `uproxy` seamlessly freezes your active downloads, voice calls, and streams, and resumes them the millisecond you regain internet access—without dropping a single byte.

---

## 🏗️ Topological Architecture

`uproxy` achieves its resiliency by strictly layering application, cryptography, reliability, and socket behaviors into a symmetrical, 4-tier architecture.

```text
[ Browser / Application ]
       │ (SOCKS5 TCP & UDP)
┌──────▼───────────────────────────┐
│ uproxy-client                    │
│  1. SOCKS5: App Demultiplexer    │
│  2. SSH: ChaCha20 Encryption     │
│  3. KCP: Reliable UDP Transport  │
│  4. ResilientPacketConn (Socket) │
└──────┬───────────────────────────┘
       │ (Encrypted KCP over UDP)   <-- The Uninterruptible Link
┌──────▼───────────────────────────┐
│ uproxy-server                    │
│  4. ResilientPacketConn (Socket) │
│  3. KCP: Reliable UDP Transport  │
│  2. SSH: Auth & Multiplexer      │
│  1. SOCKS5: TCP/UDP NAT Router   │
└──────┬───────────────────────────┘
       │ (Raw TCP & UDP)
[ The Internet (e.g., Discord) ]
```

---

## ✨ Core Features

### 🛡️ The "Uninterruptible" Socket (`ResilientPacketConn`)
Standard TCP/UDP proxies instantly crash when your OS network interface changes (yielding an `ENETUNREACH` kernel error). 
`uproxy` intercepts these fatal hardware drops, silently swallows them, artificially freezes the transport layer to prevent timeout panics, and frantically rebinds to your new network interface in the background. Your connections survive IP changes, Wi-Fi toggles, and cellular handoffs.

### 🚀 Vendored & Purified KCP Transport
Instead of TCP, `uproxy` routes traffic over a heavily modified, vendored version of `kcp-go`. 
- **1-Hour Flights:** Hardcoded KCP death-timers were rewritten. The client and server actively synchronize heartbeats to allow a configurable `--idle-timeout` (default 1 hour) where you can be entirely offline without the connection dying.
- **Lossy Mobile Ready:** Congestion control is disabled by default. If a cellular tower drops a packet, `uproxy` blasts right through it instead of throttling your bandwidth.

### 🔑 Native SSH Cryptography (No Passwords, No X.509)
`uproxy` runs a mathematically pure OpenSSH tunnel directly over the KCP transport.
- **Client Auth:** No passwords. It loads your local `~/.ssh/id_ed25519` and verifies it against the server's standard `~/.ssh/authorized_keys`.
- **Server Auth (TOFU):** Protects against MITM attacks. The client checks the server's fingerprint against your `~/.ssh/known_hosts`, throwing the classic OpenSSH terminal prompt if the server is unknown.

### 🌐 Full SOCKS5 (TCP + UDP) Multiplexing
Fully supports the SOCKS5 spec (`CONNECT` and `UDP ASSOCIATE`).
- **Dedicated Channels:** Every single SOCKS5 target (e.g., a DNS lookup, a Discord voice call, a YouTube video) is allocated its own dedicated, isolated SSH channel. 
- **True UDP NAT:** UDP packets are cleanly framed, routed through the SSH tunnel, and dialed via dedicated sockets on the server side to prevent Head-of-Line blocking.

### ⚡ Extreme Performance
- **Zero-Copy Memory:** TCP data is copied bidirectionally using a global `sync.Pool` of 32KB buffers (`io.CopyBuffer`), resulting in a flat memory curve with zero Garbage Collection thrashing under gigabit loads.
- **Microsecond Latency:** Upstream proxy sockets rigorously disable Nagle's Algorithm (`TCP_NODELAY`), and OS-level UDP sockets are aggressively tuned to 4MB buffers to prevent kernel-level packet drops.

### 📊 Rich Structured Telemetry
All legacy standard logging has been eradicated in favor of `log/slog`. Wait 30 seconds, and the transport layer emits zero-cost lock-free atomic telemetry mapping exactly how many packets were sent, received, dropped, or rebounded.

---

## 🛠️ Getting Started

### 1. Build from Source
Ensure you have Go 1.22+ installed.
```bash
# Build server and client for amd64
go build -o bin/uproxy-server-amd64 ./cmd/uproxy-server
go build -o bin/uproxy-client-amd64 ./cmd/uproxy-client

# Or build for arm64
GOARCH=arm64 go build -o bin/uproxy-server-arm64 ./cmd/uproxy-server
GOARCH=arm64 go build -o bin/uproxy-client-arm64 ./cmd/uproxy-client
```

### 2. Configure Authentication
`uproxy` uses standard OpenSSH files for authentication.
1. Make sure the user running `uproxy-client` has an SSH key at `~/.ssh/id_ed25519` or `~/.ssh/id_rsa`.
2. Copy the public key (`id_ed25519.pub`) into the `~/.ssh/authorized_keys` file of the user running `uproxy-server`.

### 3. Run the Server
```bash
# Start the server listening on port 6000
./bin/uproxy-server-amd64 --listen :6000

# (Optional) Force the server to route traffic out of a specific VPN interface
./bin/uproxy-server-amd64 --listen :6000 --outbound tun0

# Or use the systemd control script
sudo ./scripts/uproxy-serverctl.sh start
```

### 4. Run the Client
```bash
# Connect to the server and open a local SOCKS5 proxy on port 1080
./bin/uproxy-client-amd64 --server 203.0.113.50:6000 --listen 127.0.0.1:1080

# Or use the systemd control script
sudo ./scripts/uproxy-clientctl.sh start
```
*Note: On your first connection, the client will prompt your terminal to accept the server's host key, exactly like OpenSSH.*

---

## 🎛️ Control Scripts

`uproxy` includes systemd-based control scripts for managing the client and server as system services.

### Server Control (`uproxy-serverctl.sh`)
```bash
# Available commands
sudo ./scripts/uproxy-serverctl.sh start    # Start the server
sudo ./scripts/uproxy-serverctl.sh stop     # Stop the server
sudo ./scripts/uproxy-serverctl.sh restart  # Restart the server
sudo ./scripts/uproxy-serverctl.sh reload   # Reload configuration
sudo ./scripts/uproxy-serverctl.sh status   # Check service status
sudo ./scripts/uproxy-serverctl.sh health   # Check server health
sudo ./scripts/uproxy-serverctl.sh logs     # View logs
sudo ./scripts/uproxy-serverctl.sh tail     # Follow logs in real-time
```

### Client Control (`uproxy-clientctl.sh`)
```bash
# Available commands
sudo ./scripts/uproxy-clientctl.sh start    # Start the client
sudo ./scripts/uproxy-clientctl.sh stop     # Stop the client
sudo ./scripts/uproxy-clientctl.sh restart  # Restart the client
sudo ./scripts/uproxy-clientctl.sh reload   # Reload configuration
sudo ./scripts/uproxy-clientctl.sh status   # Check service status
sudo ./scripts/uproxy-clientctl.sh health   # Check client health
sudo ./scripts/uproxy-clientctl.sh logs     # View logs
sudo ./scripts/uproxy-clientctl.sh tail     # Follow logs in real-time
```

**Configuration:** Edit the scripts to customize:
- Binary paths and architecture (amd64/arm64)
- Listen addresses and ports
- Server endpoints
- KCP parameters
- Timeouts and buffer sizes

---

## ⚙️ Configuration & Tuning

Both the Client and Server share perfectly symmetrical CLI flags, allowing you to tune the proxy for different environments.

```text
Network Resilience & Timeouts:
  --idle-timeout        Idle timeout before giving up on network (default 1h)
  --reconnect-interval  Interval to retry binding UDP socket on drop (default 1s)
  --ssh-timeout         Client-only: Timeout for the initial SSH handshake (default 10s)
  --proxy-dial-timeout  Server-only: Timeout for dialing upstream targets (default 5s)

Buffer Tuning (High Speed):
  --tcp-buf             TCP copy buffer size per SOCKS5 stream (default 32768)
  --udp-sockbuf         OS UDP socket buffer size (default 4194304 - 4MB)

KCP Protocol Tuning:
  --kcp-nodelay         KCP nodelay mode (default 1 - enabled)
  --kcp-interval        KCP internal timer interval in ms (default 10)
  --kcp-resend          KCP fast resend mode (default 2)
  --kcp-nc              KCP disable congestion control (default 1 - disabled for mobile)
  --kcp-sndwnd          KCP send window size (default 4096)
  --kcp-rcvwnd          KCP receive window size (default 4096)
  --kcp-mtu             KCP maximum transmission unit (default 1350)

Logging & Telemetry:
  --log-level           Log level (debug, info, warn, error) (default "info")
  --log-format          Log format (console, json) (default "console")
```

### 📡 Telemetry Examples
Run with `--log-format json` to pipe telemetry into Datadog, ELK, or `jq`.

**Stream Telemetry:**
```json
{"time":"2026-02-28T16:00:00Z", "level":"INFO", "msg":"Stream closed", "layer":"proxy", "role":"socks5_client_tcp", "target":"youtube.com:443", "tx_bytes": 1500, "rx_bytes": 5000000, "duration": "4m30s"}
```

**Hardware Drop Telemetry:**
```json
{"time":"2026-02-28T16:05:00Z", "level":"WARN", "msg":"Network interface drop detected. Attempting to rebind socket...", "layer":"resilient"}
```

---

## 📂 Codebase Topology

The repository adheres to strict, idiomatic Go architectural symmetry:

*   **`cmd/`**: The entrypoints. `uproxy-client` and `uproxy-server` handle CLI flags, bootstrap the environment, and wire the layers together.
*   **`internal/kcp/`**: A pruned, vendored version of `xtaci/kcp-go`. Stripped of unused cryptography/FEC to provide a mathematically pure, unencrypted reliable UDP transport.
*   **`internal/uproxy/`**: The core framework. Handles the `ResilientPacketConn` socket swallowing, native `crypto/ssh` handshaking, zero-copy `proxy.go` buffering, and system-level interface routing.
*   **`internal/socks5/`**: A pristine, custom-built application layer. Symmetrically parses and routes SOCKS5 TCP (`tcp_tunnel.go`) and UDP (`udp_tunnel.go`) frames independently of the underlying transport.

---
*Built for absolute resilience.*
