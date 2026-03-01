#!/usr/bin/env bash
#
# uproxy-clientctl.sh - Control script for uproxy-client daemon
#
# Usage: ./uproxy-clientctl.sh {start|stop|restart|reload|status|logs|tail|health}
#
# Environment variables:
#   SERVER              - Remote server address (REQUIRED, e.g., 203.0.113.50:6000)
#   MODE                - Operating mode: auto|socks5|tun (default: auto, uses socks5 unless TUN_IP is set)
#   LISTEN              - Local SOCKS5 listen address (default: 127.0.0.1:1080)
#   TUN_NAME            - TUN device name (default: tun0)
#   TUN_MTU             - TUN interface MTU (default: 1400)
#   TUN_ROUTES          - Comma-separated routes to add (e.g., 0.0.0.0/0,::/0)
#   SSH_DIR             - SSH directory (default: ~/.ssh)
#   SSH_PRIVATE_KEY     - SSH private key file (default: ~/.ssh/id_ed25519 or ~/.ssh/id_rsa)
#   SSH_KNOWN_HOSTS     - SSH known_hosts file (default: ~/.ssh/known_hosts)
#   LOG_LEVEL           - Log level: debug|info|warn|error (default: info)
#   LOG_FORMAT          - Log format: console|json (default: console)
#   IDLE_TIMEOUT        - Idle timeout duration (default: 1h)
#   SSH_TIMEOUT         - SSH handshake timeout (default: 10s)
#   RECONNECT_INTERVAL  - Reconnect interval on network drop (default: 1s)
#   TCP_BUF             - TCP buffer size per stream (default: 32768)
#   UDP_SOCKBUF         - UDP socket buffer size (default: 4194304)
#   KCP_NODELAY         - KCP nodelay mode (default: 1)
#   KCP_INTERVAL        - KCP timer interval in ms (default: 10)
#   KCP_RESEND          - KCP fast resend mode (default: 2)
#   KCP_NC              - KCP disable congestion control (default: 1)
#   KCP_SNDWND          - KCP send window (default: 4096)
#   KCP_RCVWND          - KCP receive window (default: 4096)
#   KCP_MTU             - KCP MTU (default: 1350)
#   EXTRA_FLAGS         - Additional flags to pass to uproxy-client
#

set -euo pipefail

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly PID_FILE="$PROJECT_ROOT/uproxy-client.pid"
readonly LOG_FILE="$PROJECT_ROOT/uproxy-client.nohup.log"
readonly BINARY_DIR="$PROJECT_ROOT/bin"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Detect architecture and select binary
detect_binary() {
    local arch
    arch="$(uname -m)"
    
    case "$arch" in
        x86_64)
            echo "$BINARY_DIR/uproxy-client-amd64"
            ;;
        aarch64|arm64)
            echo "$BINARY_DIR/uproxy-client-arm64"
            ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# Validate binary exists and is executable
validate_binary() {
    local binary="$1"
    
    if [[ ! -f "$binary" ]]; then
        log_error "Binary not found: $binary"
        log_info "Please build the project first: go build -o $binary ./cmd/uproxy-client"
        exit 1
    fi
    
    if [[ ! -x "$binary" ]]; then
        log_error "Binary is not executable: $binary"
        log_info "Run: chmod +x $binary"
        exit 1
    fi
}

# Build command line arguments
build_args() {
    local args=()
    
    # Server address (required)
    if [[ -z "${SERVER:-}" ]]; then
        log_error "SERVER environment variable is required"
        log_info "Example: SERVER=203.0.113.50:6000 $0 start"
        exit 1
    fi
    args+=(--server "$SERVER")
    
    # Mode selection: auto mode by default (binary decides based on privileges)
    args+=(--mode "${MODE:-auto}")
    
    # SOCKS5 listen address (used for SOCKS5 mode or as fallback)
    args+=(--listen "${LISTEN:-127.0.0.1:1080}")
    
    # TUN parameters (IPs are assigned by server, only device config needed)
    args+=(--tun-name "${TUN_NAME:-tun0}")
    args+=(--tun-mtu "${TUN_MTU:-1400}")
    if [[ -n "${TUN_ROUTES:-}" ]]; then
        args+=(--tun-routes "$TUN_ROUTES")
    fi
    
    # SSH configuration
    if [[ -n "${SSH_DIR:-}" ]]; then
        args+=(--ssh-dir "$SSH_DIR")
    fi
    if [[ -n "${SSH_PRIVATE_KEY:-}" ]]; then
        args+=(--ssh-private-key "$SSH_PRIVATE_KEY")
    fi
    if [[ -n "${SSH_KNOWN_HOSTS:-}" ]]; then
        args+=(--ssh-known-hosts "$SSH_KNOWN_HOSTS")
    fi
    
    # Log level
    args+=(--log-level "${LOG_LEVEL:-info}")
    
    # Log format
    args+=(--log-format "${LOG_FORMAT:-console}")
    
    # Timeouts
    args+=(--idle-timeout "${IDLE_TIMEOUT:-1h}")
    args+=(--ssh-timeout "${SSH_TIMEOUT:-10s}")
    args+=(--reconnect-interval "${RECONNECT_INTERVAL:-1s}")
    
    # Buffer sizes
    args+=(--tcp-buf "${TCP_BUF:-32768}")
    args+=(--udp-sockbuf "${UDP_SOCKBUF:-4194304}")
    
    # KCP parameters
    args+=(--kcp-nodelay "${KCP_NODELAY:-1}")
    args+=(--kcp-interval "${KCP_INTERVAL:-10}")
    args+=(--kcp-resend "${KCP_RESEND:-2}")
    args+=(--kcp-nc "${KCP_NC:-1}")
    args+=(--kcp-sndwnd "${KCP_SNDWND:-4096}")
    args+=(--kcp-rcvwnd "${KCP_RCVWND:-4096}")
    args+=(--kcp-mtu "${KCP_MTU:-1350}")
    
    # Extra flags
    if [[ -n "${EXTRA_FLAGS:-}" ]]; then
        # shellcheck disable=SC2206
        args+=($EXTRA_FLAGS)
    fi
    
    echo "${args[@]}"
}

# Check if client is running
is_running() {
    if [[ ! -f "$PID_FILE" ]]; then
        return 1
    fi
    
    local pid
    pid="$(cat "$PID_FILE")"
    
    if [[ -z "$pid" ]]; then
        return 1
    fi
    
    if kill -0 "$pid" 2>/dev/null; then
        return 0
    else
        # PID file exists but process is dead
        rm -f "$PID_FILE"
        return 1
    fi
}

# Get PID from file
get_pid() {
    if [[ -f "$PID_FILE" ]]; then
        cat "$PID_FILE"
    fi
}

# Start the client
start_client() {
    if is_running; then
        log_warn "Client is already running (PID: $(get_pid))"
        return 0
    fi
    
    local binary
    binary="$(detect_binary)"
    validate_binary "$binary"
    
    local args
    args="$(build_args)"
    
    log_info "Starting uproxy-client..."
    log_info "Binary: $binary"
    log_info "Arguments: $args"
    log_info "Log file: $LOG_FILE"
    
    # Start client with nohup
    # shellcheck disable=SC2086
    nohup "$binary" $args > "$LOG_FILE" 2>&1 &
    local pid=$!
    
    # Save PID
    echo "$pid" > "$PID_FILE"
    
    # Wait a moment and check if it's still running
    sleep 1
    
    if is_running; then
        log_success "Client started successfully (PID: $pid)"
        return 0
    else
        log_error "Client failed to start. Check logs: $LOG_FILE"
        rm -f "$PID_FILE"
        return 1
    fi
}

# Stop the client
stop_client() {
    if ! is_running; then
        log_warn "Client is not running"
        return 0
    fi
    
    local pid
    pid="$(get_pid)"
    
    log_info "Stopping uproxy-client (PID: $pid)..."
    
    # Send SIGTERM for graceful shutdown
    if kill -TERM "$pid" 2>/dev/null; then
        # Wait for process to exit (max 10 seconds)
        local count=0
        while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
            sleep 1
            ((count++))
        done
        
        # If still running, force kill
        if kill -0 "$pid" 2>/dev/null; then
            log_warn "Client did not stop gracefully, forcing shutdown..."
            kill -KILL "$pid" 2>/dev/null || true
            sleep 1
        fi
    fi
    
    # Clean up PID file
    rm -f "$PID_FILE"
    
    if ! is_running; then
        log_success "Client stopped successfully"
        return 0
    else
        log_error "Failed to stop client"
        return 1
    fi
}

# Restart the client
restart_client() {
    log_info "Restarting uproxy-client..."
    stop_client
    sleep 1
    start_client
}

# Reload the client (graceful restart)
reload_client() {
    if ! is_running; then
        log_warn "Client is not running, starting instead..."
        start_client
        return $?
    fi
    
    local pid
    pid="$(get_pid)"
    
    log_info "Reloading uproxy-client (PID: $pid)..."
    
    # Send SIGHUP for graceful reload (if supported)
    if kill -HUP "$pid" 2>/dev/null; then
        log_success "Reload signal sent to client"
        return 0
    else
        log_warn "Client does not support reload, performing restart instead..."
        restart_client
        return $?
    fi
}

# Show client status
show_status() {
    if is_running; then
        local pid
        pid="$(get_pid)"
        log_success "Client is running (PID: $pid)"
        
        # Show process info
        if command -v ps >/dev/null 2>&1; then
            echo ""
            ps -p "$pid" -o pid,ppid,user,%cpu,%mem,vsz,rss,tty,stat,start,time,command
        fi
        
        return 0
    else
        log_warn "Client is not running"
        return 1
    fi
}

# Health check
health_check() {
    if ! is_running; then
        log_error "Client is not running"
        return 1
    fi
    
    local pid
    pid="$(get_pid)"
    
    log_info "Performing health check..."
    log_info "PID: $pid"
    
    # Check if process is responsive
    if kill -0 "$pid" 2>/dev/null; then
        log_success "Process is alive and responsive"
    else
        log_error "Process is not responsive"
        return 1
    fi
    
    # Check log file for recent errors
    if [[ -f "$LOG_FILE" ]]; then
        local error_count
        error_count=$(tail -n 100 "$LOG_FILE" | grep -c "ERROR" || true)
        
        if [[ $error_count -gt 0 ]]; then
            log_warn "Found $error_count errors in recent logs"
        else
            log_success "No recent errors in logs"
        fi
        
        # Check for connection status
        if tail -n 50 "$LOG_FILE" | grep -q "Connected to server via KCP+SSH"; then
            log_success "Client is connected to server"
        else
            log_warn "No recent connection confirmation in logs"
        fi
    fi
    
    return 0
}

# Show logs
show_logs() {
    if [[ ! -f "$LOG_FILE" ]]; then
        log_error "Log file not found: $LOG_FILE"
        return 1
    fi
    
    less +G "$LOG_FILE"
}

# Tail logs
tail_logs() {
    if [[ ! -f "$LOG_FILE" ]]; then
        log_error "Log file not found: $LOG_FILE"
        return 1
    fi
    
    tail -f "$LOG_FILE"
}

# Show usage
show_usage() {
    cat <<EOF
Usage: $0 {start|stop|restart|reload|status|health|logs|tail}

Commands:
    start       Start the uproxy-client daemon
    stop        Stop the uproxy-client daemon
    restart     Restart the uproxy-client daemon
    reload      Gracefully reload the client (or restart if not supported)
    status      Show client status
    health      Perform health check
    logs        View client logs (less)
    tail        Tail client logs (follow)

Environment Variables:
    SERVER              Remote server address (REQUIRED, e.g., 203.0.113.50:6000)
    MODE                Operating mode: auto|socks5|tun (default: auto)
    LISTEN              Local SOCKS5 listen address (default: 127.0.0.1:1080)
    TUN_NAME            TUN device name (default: tun0)
    TUN_MTU             TUN interface MTU (default: 1400)
    TUN_ROUTES          Comma-separated routes to add (e.g., 0.0.0.0/0,::/0)
    SSH_DIR             SSH directory (default: ~/.ssh)
    SSH_PRIVATE_KEY     SSH private key file (default: ~/.ssh/id_ed25519 or ~/.ssh/id_rsa)
    SSH_KNOWN_HOSTS     SSH known_hosts file (default: ~/.ssh/known_hosts)
    LOG_LEVEL           Log level: debug|info|warn|error (default: info)
    LOG_FORMAT          Log format: console|json (default: console)
    IDLE_TIMEOUT        Idle timeout duration (default: 1h)
    SSH_TIMEOUT         SSH handshake timeout (default: 10s)
    RECONNECT_INTERVAL  Reconnect interval on network drop (default: 1s)
    TCP_BUF             TCP buffer size per stream (default: 32768)
    UDP_SOCKBUF         UDP socket buffer size (default: 4194304)
    KCP_NODELAY         KCP nodelay mode (default: 1)
    KCP_INTERVAL        KCP timer interval in ms (default: 10)
    KCP_RESEND          KCP fast resend mode (default: 2)
    KCP_NC              KCP disable congestion control (default: 1)
    KCP_SNDWND          KCP send window (default: 4096)
    KCP_RCVWND          KCP receive window (default: 4096)
    KCP_MTU             KCP MTU (default: 1350)
    EXTRA_FLAGS         Additional flags to pass to uproxy-client

Examples:
    # Start in auto mode (default - uses TUN if root, SOCKS5 otherwise)
    SERVER=203.0.113.50:6000 $0 start
    
    # Start in TUN mode explicitly (requires root privileges)
    sudo SERVER=203.0.113.50:6000 MODE=tun $0 start
    
    # Start in TUN mode with custom routes
    sudo SERVER=203.0.113.50:6000 MODE=tun TUN_ROUTES=0.0.0.0/0,::/0 $0 start
    
    # Start with custom listen address and debug logging
    SERVER=203.0.113.50:6000 LISTEN=127.0.0.1:8080 LOG_LEVEL=debug $0 start
    
    # Start with custom KCP parameters
    SERVER=203.0.113.50:6000 KCP_MTU=1400 KCP_SNDWND=8192 $0 start

EOF
}

# Main
main() {
    local command="${1:-}"
    
    if [[ -z "$command" ]]; then
        show_usage
        exit 1
    fi
    
    case "$command" in
        start)
            start_client
            ;;
        stop)
            stop_client
            ;;
        restart)
            restart_client
            ;;
        reload)
            reload_client
            ;;
        status)
            show_status
            ;;
        health)
            health_check
            ;;
        logs)
            show_logs
            ;;
        tail)
            tail_logs
            ;;
        *)
            log_error "Unknown command: $command"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
