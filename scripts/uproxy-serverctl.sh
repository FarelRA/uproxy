#!/usr/bin/env bash
#
# uproxy-serverctl.sh - Control script for uproxy-server daemon
#
# Usage: ./uproxy-serverctl.sh {start|stop|restart|reload|status|logs|tail|health}
#
# Environment variables:
#   LISTEN              - Listen address (default: :6000)
#   OUTBOUND            - Outbound interface name (optional)
#   LOG_LEVEL           - Log level: debug|info|warn|error (default: info)
#   LOG_FORMAT          - Log format: text|json (default: text)
#   IDLE_TIMEOUT        - Idle timeout duration (default: 5m)
#   EXTRA_FLAGS         - Additional flags to pass to uproxy-server
#   SERVER_PUBLIC_ADDR  - Public address for server (optional)
#

set -euo pipefail

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly PID_FILE="$PROJECT_ROOT/uproxy-server.pid"
readonly LOG_FILE="$PROJECT_ROOT/uproxy-server.nohup.log"
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
            echo "$BINARY_DIR/uproxy-server-amd64"
            ;;
        aarch64|arm64)
            echo "$BINARY_DIR/uproxy-server-arm64"
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
        log_info "Please build the project first: go build -o $binary ./cmd/uproxy-server"
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
    
    # Listen address
    args+=(--listen "${LISTEN:-:6000}")
    
    # Outbound interface (optional)
    if [[ -n "${OUTBOUND:-}" ]]; then
        args+=(--outbound "$OUTBOUND")
    fi
    
    # Log level
    args+=(--log-level "${LOG_LEVEL:-info}")
    
    # Log format
    args+=(--log-format "${LOG_FORMAT:-text}")
    
    # Idle timeout
    args+=(--idle-timeout "${IDLE_TIMEOUT:-5m}")
    
    # Public address (optional)
    if [[ -n "${SERVER_PUBLIC_ADDR:-}" ]]; then
        args+=(--public-addr "$SERVER_PUBLIC_ADDR")
    fi
    
    # Extra flags
    if [[ -n "${EXTRA_FLAGS:-}" ]]; then
        # shellcheck disable=SC2206
        args+=($EXTRA_FLAGS)
    fi
    
    echo "${args[@]}"
}

# Check if server is running
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

# Start the server
start_server() {
    if is_running; then
        log_warn "Server is already running (PID: $(get_pid))"
        return 0
    fi
    
    local binary
    binary="$(detect_binary)"
    validate_binary "$binary"
    
    local args
    args="$(build_args)"
    
    log_info "Starting uproxy-server..."
    log_info "Binary: $binary"
    log_info "Arguments: $args"
    log_info "Log file: $LOG_FILE"
    
    # Start server with nohup
    # shellcheck disable=SC2086
    nohup "$binary" $args > "$LOG_FILE" 2>&1 &
    local pid=$!
    
    # Save PID
    echo "$pid" > "$PID_FILE"
    
    # Wait a moment and check if it's still running
    sleep 1
    
    if is_running; then
        log_success "Server started successfully (PID: $pid)"
        return 0
    else
        log_error "Server failed to start. Check logs: $LOG_FILE"
        rm -f "$PID_FILE"
        return 1
    fi
}

# Stop the server
stop_server() {
    if ! is_running; then
        log_warn "Server is not running"
        return 0
    fi
    
    local pid
    pid="$(get_pid)"
    
    log_info "Stopping uproxy-server (PID: $pid)..."
    
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
            log_warn "Server did not stop gracefully, forcing shutdown..."
            kill -KILL "$pid" 2>/dev/null || true
            sleep 1
        fi
    fi
    
    # Clean up PID file
    rm -f "$PID_FILE"
    
    if ! is_running; then
        log_success "Server stopped successfully"
        return 0
    else
        log_error "Failed to stop server"
        return 1
    fi
}

# Restart the server
restart_server() {
    log_info "Restarting uproxy-server..."
    stop_server
    sleep 1
    start_server
}

# Reload the server (graceful restart)
reload_server() {
    if ! is_running; then
        log_warn "Server is not running, starting instead..."
        start_server
        return $?
    fi
    
    local pid
    pid="$(get_pid)"
    
    log_info "Reloading uproxy-server (PID: $pid)..."
    
    # Send SIGHUP for graceful reload (if supported)
    if kill -HUP "$pid" 2>/dev/null; then
        log_success "Reload signal sent to server"
        return 0
    else
        log_warn "Server does not support reload, performing restart instead..."
        restart_server
        return $?
    fi
}

# Show server status
show_status() {
    if is_running; then
        local pid
        pid="$(get_pid)"
        log_success "Server is running (PID: $pid)"
        
        # Show process info
        if command -v ps >/dev/null 2>&1; then
            echo ""
            ps -p "$pid" -o pid,ppid,user,%cpu,%mem,vsz,rss,tty,stat,start,time,command
        fi
        
        return 0
    else
        log_warn "Server is not running"
        return 1
    fi
}

# Health check
health_check() {
    if ! is_running; then
        log_error "Server is not running"
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
    start       Start the uproxy-server daemon
    stop        Stop the uproxy-server daemon
    restart     Restart the uproxy-server daemon
    reload      Gracefully reload the server (or restart if not supported)
    status      Show server status
    health      Perform health check
    logs        View server logs (less)
    tail        Tail server logs (follow)

Environment Variables:
    LISTEN              Listen address (default: :6000)
    OUTBOUND            Outbound interface name (optional)
    LOG_LEVEL           Log level: debug|info|warn|error (default: info)
    LOG_FORMAT          Log format: text|json (default: text)
    IDLE_TIMEOUT        Idle timeout duration (default: 5m)
    EXTRA_FLAGS         Additional flags to pass to uproxy-server
    SERVER_PUBLIC_ADDR  Public address for server (optional)

Examples:
    # Start with custom listen address
    LISTEN=:8080 $0 start
    
    # Start with debug logging
    LOG_LEVEL=debug $0 start
    
    # Start with outbound interface
    OUTBOUND=eth0 $0 start

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
            start_server
            ;;
        stop)
            stop_server
            ;;
        restart)
            restart_server
            ;;
        reload)
            reload_server
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
