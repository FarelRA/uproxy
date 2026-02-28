#!/usr/bin/env bash
set -eo pipefail

# Control script for uproxy-server
# Uses nohup to run the server in the background and saves its PID.
#
# Environment overrides:
#   LISTEN=":6000"
#   OUTBOUND="tun0"         # optional; forces upstream TCP source/interface
#   LOG_LEVEL="info"        # optional; debug, info, warn, error
#   LOG_FORMAT="console"    # optional; console, json
#   IDLE_TIMEOUT="1h"       # optional; idle timeout before giving up on network
#   EXTRA_FLAGS=""          # optional; appended as-is
#
# Convenience:
#   SERVER_PUBLIC_ADDR=""    # override host/IP used in printed client command

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"
LOG_FILE="${ROOT_DIR}/uproxy-server.nohup.log"
PID_FILE="${ROOT_DIR}/uproxy-server.pid"

LISTEN="${LISTEN:-:6000}"
OUTBOUND="${OUTBOUND:-}"
LOG_LEVEL="${LOG_LEVEL:-info}"
LOG_FORMAT="${LOG_FORMAT:-console}"
IDLE_TIMEOUT="${IDLE_TIMEOUT:-1h}"
EXTRA_FLAGS="${EXTRA_FLAGS:-}"

SERVER_PUBLIC_ADDR="${SERVER_PUBLIC_ADDR:-}"

pick_bin() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64) echo "${BIN_DIR}/uproxy-server-linux-amd64" ;;
    aarch64|arm64) echo "${BIN_DIR}/uproxy-server-linux-arm64" ;;
    *) echo "${BIN_DIR}/uproxy-server" ;;
  esac
}

cmdline() {
  local bin="$1"
  local args=()
  args+=("$bin")
  args+=("--listen" "$LISTEN")
  if [[ -n "$OUTBOUND" ]]; then
    args+=("--outbound" "$OUTBOUND")
  fi
  args+=("--log-level" "$LOG_LEVEL")
  args+=("--log-format" "$LOG_FORMAT")
  args+=("--idle-timeout" "$IDLE_TIMEOUT")
  if [[ -n "$EXTRA_FLAGS" ]]; then
    args+=($EXTRA_FLAGS)
  fi
  printf '%q ' "${args[@]}"
}

parse_port() {
  local addr="$1"
  if [[ "$addr" =~ \]:(.+)$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  echo "${addr##*:}"
}

guess_host_for_clients() {
  if [[ -n "$SERVER_PUBLIC_ADDR" ]]; then
    echo "$SERVER_PUBLIC_ADDR"
    return 0
  fi
  local ips
  ips="$(hostname -I 2>/dev/null || true)"
  if [[ -n "$ips" ]]; then
    echo "${ips%% *}"
    return 0
  fi
  hostname -f 2>/dev/null || hostname
}

print_client_command() {
  local listen_port host
  listen_port="$(parse_port "$LISTEN")"
  host="$(guess_host_for_clients)"

  echo "----"
  echo "Client command:"
  echo "  bin/uproxy-client-linux-<amd64|arm64> \\"
  echo "    --server ${host}:${listen_port} \\"
  echo "    --listen 127.0.0.1:1080 \\"
  echo "    --idle-timeout ${IDLE_TIMEOUT}"
  echo "----"
}

start() {
  local bin
  bin="$(pick_bin)"
  if [[ ! -x "$bin" ]]; then
    echo "error: server binary not found or not executable at $bin"
    exit 1
  fi
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "server is already running (pid $(cat "$PID_FILE"))"
    exit 0
  fi

  echo "starting: $(cmdline "$bin")"
  nohup "$bin" \
    --listen "$LISTEN" \
    ${OUTBOUND:+--outbound "$OUTBOUND"} \
    --log-level "$LOG_LEVEL" \
    --log-format "$LOG_FORMAT" \
    --idle-timeout "$IDLE_TIMEOUT" \
    $EXTRA_FLAGS \
    >>"$LOG_FILE" 2>&1 &
  local pid=$!
  echo "$pid" > "$PID_FILE"
  echo "started (pid $pid)"

  print_client_command
}

stop() {
  if [[ ! -f "$PID_FILE" ]]; then
    echo "server not running (no pidfile)"
    exit 0
  fi
  local pid
  pid="$(cat "$PID_FILE")"
  if kill -0 "$pid" 2>/dev/null; then
    echo "stopping $pid..."
    kill "$pid"
    # wait up to 5s
    for _ in {1..5}; do
      if kill -0 "$pid" 2>/dev/null; then
        sleep 1
      else
        break
      fi
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "force stopping $pid..."
      kill -9 "$pid"
    fi
  else
    echo "server not running (pid $pid dead)"
  fi
  rm -f "$PID_FILE"
  echo "stopped"
}

status() {
  if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "running (pid $(cat "$PID_FILE"))"
    exit 0
  else
    echo "stopped"
    exit 3
  fi
}

logs() {
  if [[ -f "$LOG_FILE" ]]; then
    cat "$LOG_FILE"
  else
    echo "no logs found at $LOG_FILE"
  fi
}

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop
    start
    ;;
  status)
    status
    ;;
  logs)
    logs
    ;;
  tail)
    if [[ -f "$LOG_FILE" ]]; then
      tail -f "$LOG_FILE"
    else
      echo "no logs found at $LOG_FILE"
    fi
    ;;
  *)
    echo "Usage: \$0 <start|stop|restart|status|logs|tail>"
    echo "Environment variables:"
    cat <<EOF
  LISTEN=\$LISTEN
  OUTBOUND=\${OUTBOUND:-"(unset)"}
  LOG_LEVEL=\$LOG_LEVEL
  LOG_FORMAT=\$LOG_FORMAT
  IDLE_TIMEOUT=\$IDLE_TIMEOUT
  SERVER_PUBLIC_ADDR=\${SERVER_PUBLIC_ADDR:-"(unset)"}
  LOG_FILE=\$LOG_FILE
  PID_FILE=\$PID_FILE
EOF
    exit 1
    ;;
esac
