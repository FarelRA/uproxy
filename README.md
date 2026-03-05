# uproxy (The Uninterruptible Proxy)

**uproxy** is a highly optimized, cryptographically secure, and completely uninterruptible proxy supporting both SOCKS5 and TUN modes. 

It is designed for one specific purpose: **to keep your connections alive no matter what happens to your physical network.** Whether you are switching from Wi-Fi to Cellular, driving through a tunnel, or closing your laptop lid for a 1-hour flight, `uproxy` seamlessly freezes your active downloads, voice calls, and streams, and resumes them the millisecond you regain internet access—without dropping a single byte.

---

## 🏗️ Topological Architecture

`uproxy` achieves its resiliency by strictly layering application, cryptography, reliability, and socket behaviors into a symmetrical, 4-tier architecture.

```text
[ Browser / Application ]
       │ (SOCKS5 TCP & UDP or TUN IP packets)
┌──────▼───────────────────────────┐
│ uproxy-client                    │
│  1. SOCKS5 or TUN: App Layer     │
│  2. QUIC: Multiplexed Streams    │
│  3. mTLS: Mutual Authentication  │
│  4. UDP Socket                   │
└──────┬───────────────────────────┘
       │ (QUIC+mTLS over UDP)       <-- The Uninterruptible Link
┌──────▼───────────────────────────┐
│ uproxy-server                    │
│  4. UDP Socket                   │
│  3. mTLS: Mutual Authentication  │
│  2. QUIC: Stream Demultiplexer   │
│  1. SOCKS5 or TUN: Packet Router │
└──────┬───────────────────────────┘
       │ (Raw TCP & UDP)
[ The Internet (e.g., Discord) ]
```

---

## ✨ Core Features

### 🚀 QUIC Transport with Connection Migration
`uproxy` uses QUIC (Quick UDP Internet Connections) as its transport protocol, providing native connection migration and multiplexing.
- **Seamless Network Changes:** QUIC's built-in connection migration allows your connections to survive IP address changes, Wi-Fi to cellular handoffs, and network interface switches without dropping.
- **1-Hour Flights:** Configurable idle timeout (default 1 hour) allows you to be entirely offline without the connection dying. QUIC's keep-alive mechanism maintains the connection state.
- **Multiplexed Streams:** Multiple streams share a single QUIC connection, eliminating head-of-line blocking and reducing latency.
- **0-RTT Resumption:** Subsequent connections can resume with zero round-trip time, dramatically reducing reconnection overhead.

### 🔑 SSH-based mTLS Authentication (No Passwords)
`uproxy` uses mutual TLS (mTLS) for authentication and encryption, while maintaining OpenSSH's familiar key management workflow.
- **Client Auth:** No passwords. It loads your local `~/.ssh/id_ed25519` or `~/.ssh/id_rsa`, converts it to an X.509 certificate on-the-fly, and verifies it against the server's standard `~/.ssh/authorized_keys`.
- **Server Auth (TOFU):** Protects against MITM attacks. The client checks the server's certificate fingerprint against your `~/.ssh/known_hosts`, throwing the classic OpenSSH terminal prompt if the server is unknown.
- **Best of Both Worlds:** You keep using your existing SSH keys and authorized_keys files, but benefit from QUIC's modern TLS 1.3 encryption and perfect forward secrecy.

### 🌐 Dual Mode: SOCKS5 & TUN
**SOCKS5 Mode (Default):** Fully supports the SOCKS5 spec (`CONNECT` and `UDP ASSOCIATE`).
- **Dedicated Channels:** Every single SOCKS5 target (e.g., a DNS lookup, a Discord voice call, a YouTube video) is allocated its own dedicated, isolated SSH channel. 
- **True UDP NAT:** UDP packets are cleanly framed, routed through the SSH tunnel, and dialed via dedicated sockets on the server side to prevent Head-of-Line blocking.

**TUN Mode (VPN-like):** Creates a virtual network interface for system-wide tunneling.
- **Layer 3 Tunneling:** All IP packets from the TUN device are encrypted and routed through the QUIC+mTLS transport.
- **Transparent Routing:** Applications don't need SOCKS5 support—traffic is captured at the IP layer.
- **Flexible Routing:** Configure specific routes (e.g., `0.0.0.0/0` for full VPN, or selective routes like `10.0.0.0/8`).

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

**SOCKS5 Mode (Default):**
```bash
# Connect to the server and open a local SOCKS5 proxy on port 1080
./bin/uproxy-client-amd64 --server 203.0.113.50:6000 --listen 127.0.0.1:1080

# Or use the systemd control script
sudo ./scripts/uproxy-clientctl.sh start
```

**TUN Mode (VPN-like):**
```bash
# Create a TUN interface and route all traffic through it
sudo ./bin/uproxy-client-amd64 \
  --mode tun \
  --server 203.0.113.50:6000 \
  --tun-name utun0 \
  --tun-ip 10.0.0.2 \
  --tun-netmask 255.255.255.0 \
  --tun-routes 0.0.0.0/0

# Or route only specific networks
sudo ./bin/uproxy-client-amd64 \
  --mode tun \
  --server 203.0.113.50:6000 \
  --tun-name utun0 \
  --tun-ip 10.0.0.2 \
  --tun-routes 10.0.0.0/8,192.168.0.0/16
```
*Note: TUN mode requires root privileges or `CAP_NET_ADMIN` capability.*

**TUN Mode Architecture:**

TUN mode uses a **symmetric architecture** where both client and server leverage the **system's native TCP/IP stack** for maximum efficiency and reliability:

- **Client Side**: Applications → Kernel TCP/IP stack → Client TUN device → QUIC+mTLS tunnel
- **Server Side**: QUIC+mTLS tunnel → Server TUN device → Kernel routing/NAT/forwarding → Internet (and back)

**Why this approach?**
- **Symmetric design**: Both sides use TUN devices for clean bidirectional packet flow
- **No protocol reinvention**: The kernel handles TCP state machines, checksums, fragmentation, congestion control, etc.
- **Full protocol support**: TCP, UDP, ICMP, ICMPv6, and any other IP protocol work automatically
- **Better performance**: Zero overhead from userspace protocol handling
- **More reliable**: Battle-tested kernel networking stack vs. custom implementations

The server automatically enables IP forwarding and sets up NAT/masquerading rules using iptables. All routing and forwarding decisions are handled by the kernel's networking stack. Both client and server require root privileges or `CAP_NET_ADMIN` capability to create TUN devices.

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
- QUIC parameters
- Timeouts and buffer sizes

---

## ⚙️ Configuration & Tuning

Both the Client and Server share perfectly symmetrical CLI flags, allowing you to tune the proxy for different environments.

```text
Operating Mode (Client-only):
  --mode                Operating mode: socks5 or tun (default "socks5")
  --listen              SOCKS5 listen address (socks5 mode only) (default "127.0.0.1:1080")

TUN Mode Configuration (Client-only):
  --tun-name            TUN device name (default "utun0")
  --tun-ip              TUN interface IP address (required for tun mode)
  --tun-netmask         TUN interface netmask (default "255.255.255.0")
  --tun-mtu             TUN interface MTU (default 1400)
  --tun-routes          Comma-separated routes (e.g., "0.0.0.0/0,8.8.8.8/32")

Network Resilience & Timeouts:
  --idle-timeout        Idle timeout before giving up on network (default 1h)
  --reconnect-interval  Interval to retry binding UDP socket on drop (default 1s)
  --ssh-timeout         Client-only: Timeout for the initial SSH handshake (default 10s)
  --proxy-dial-timeout  Server-only: Timeout for dialing upstream targets (default 5s)

Buffer Tuning (High Speed):
  --tcp-buf             TCP copy buffer size per SOCKS5 stream (default 32768)
  --udp-sockbuf         OS UDP socket buffer size (default 4194304 - 4MB)

QUIC Protocol Tuning:
  --quic-max-idle-timeout                Maximum idle timeout (default 1h)
  --quic-max-incoming-streams            Maximum concurrent bidirectional streams (default 1000)
  --quic-max-incoming-uni-streams        Maximum concurrent unidirectional streams (default 1000)
  --quic-initial-stream-receive-window   Initial stream receive window (default 512KB)
  --quic-max-stream-receive-window       Maximum stream receive window (default 6MB)
  --quic-initial-connection-receive-window Initial connection receive window (default 512KB)
  --quic-max-connection-receive-window   Maximum connection receive window (default 15MB)
  --quic-keep-alive-period               Keep-alive period (default 30s)
  --quic-disable-path-mtu-discovery      Disable Path MTU Discovery (default false)
  --quic-enable-0rtt                     Enable 0-RTT resumption (default true)
  --quic-handshake-timeout               Handshake timeout (default 10s)
  --quic-initial-packet-size             Initial packet size for MTU-constrained networks (default 1280)
  --quic-enable-datagrams                Enable QUIC datagrams for UDP (default true)

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
*   **`internal/quictransport/`**: QUIC transport implementation. Provides stream multiplexing, connection management, and typed stream helpers (TCP/UDP/TUN) over QUIC with mTLS authentication.
*   **`internal/uproxy/`**: The core framework. Handles SSH key loading, X.509 certificate generation, mTLS verification callbacks, and authentication workflows (authorized_keys, known_hosts, TOFU).
*   **`internal/socks5/`**: A pristine, custom-built application layer. Symmetrically parses and routes SOCKS5 TCP (`tcp_tunnel.go`) and UDP (`udp_tunnel.go`) frames over QUIC streams.
*   **`internal/tun/`**: TUN device management and IP packet handling. Provides Layer 3 tunneling capabilities for VPN-like functionality.

---
*Built for absolute resilience.*
