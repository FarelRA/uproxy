#!/usr/bin/env bash
set -euo pipefail

# Policy routing for Cloudflare WARP (tun0) by SOURCE address.
#
# Goal: do NOT warp the whole system. Only traffic that binds its
# socket source IP to the WARP interface IP will be routed via tun0.
#
# Typical use: run uproxy-server with `--outbound-iface tun0`.
# That forces upstream TCP connections to use tun0's source IP, and
# these rules route those connections via tun0.
#
# Requires: root (sudo), `ip` (iproute2).

IFACE="${IFACE:-tun0}"
TABLE="${TABLE:-100}"
PREF="${PREF:-1000}"

usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/warp-policy-routing.sh apply
  sudo ./scripts/warp-policy-routing.sh remove
  ./scripts/warp-policy-routing.sh status

Environment overrides:
  IFACE=tun0 TABLE=100 PREF=1000
EOF
}

need_ip() {
  command -v ip >/dev/null 2>&1 || { echo "error: ip command not found" >&2; exit 1; }
}

get_ipv4_cidr() {
  ip -4 addr show dev "$IFACE" 2>/dev/null | sed -n 's/.*inet \([^ ]\+\).*/\1/p' | head -n 1
}

get_ipv6_cidr() {
  ip -6 addr show dev "$IFACE" 2>/dev/null | sed -n 's/.*inet6 \([^ ]\+\).*/\1/p' | head -n 1
}

rule_exists_v4() {
  local cidr="$1"
  ip -4 rule show | grep -Fq "from ${cidr} lookup ${TABLE}"
}

rule_exists_v6() {
  local cidr="$1"
  ip -6 rule show | grep -Fq "from ${cidr} lookup ${TABLE}"
}

apply_rules() {
  need_ip

  local ip4 ip6
  ip4="$(get_ipv4_cidr || true)"
  ip6="$(get_ipv6_cidr || true)"

  if [[ -z "${ip4}" && -z "${ip6}" ]]; then
    echo "error: interface ${IFACE} has no IPv4/IPv6 addresses" >&2
    exit 1
  fi

  # Route table: default via IFACE (do not touch main table).
  # 'replace' makes this idempotent.
  if [[ -n "${ip4}" ]]; then
    ip -4 route replace table "$TABLE" default dev "$IFACE"
  fi
  if [[ -n "${ip6}" ]]; then
    ip -6 route replace table "$TABLE" default dev "$IFACE"
  fi

  # Policy rules: match on SOURCE address.
  if [[ -n "${ip4}" ]]; then
    if ! rule_exists_v4 "$ip4"; then
      ip -4 rule add pref "$PREF" from "$ip4" lookup "$TABLE"
    fi
  fi
  if [[ -n "${ip6}" ]]; then
    if ! rule_exists_v6 "$ip6"; then
      ip -6 rule add pref "$PREF" from "$ip6" lookup "$TABLE"
    fi
  fi

  ip route flush cache || true
  echo "ok: applied policy routing for ${IFACE} (table=${TABLE}, pref=${PREF})"
}

remove_rules() {
  need_ip

  local ip4 ip6
  ip4="$(get_ipv4_cidr || true)"
  ip6="$(get_ipv6_cidr || true)"

  # Remove matching rules (loop in case duplicates exist).
  if [[ -n "${ip4}" ]]; then
    while ip -4 rule show | grep -Fq "from ${ip4} lookup ${TABLE}"; do
      ip -4 rule del from "$ip4" lookup "$TABLE" 2>/dev/null || break
    done
  fi
  if [[ -n "${ip6}" ]]; then
    while ip -6 rule show | grep -Fq "from ${ip6} lookup ${TABLE}"; do
      ip -6 rule del from "$ip6" lookup "$TABLE" 2>/dev/null || break
    done
  fi

  ip -4 route del table "$TABLE" default dev "$IFACE" 2>/dev/null || true
  ip -6 route del table "$TABLE" default dev "$IFACE" 2>/dev/null || true
  ip route flush cache || true
  echo "ok: removed policy routing for ${IFACE} (table=${TABLE})"
}

status() {
  need_ip
  echo "iface=${IFACE} table=${TABLE} pref=${PREF}"
  echo "----"
  ip -brief addr show dev "$IFACE" 2>/dev/null || true
  echo "----"
  echo "IPv4 rules (filtered):"
  ip -4 rule show | grep -E "lookup ${TABLE}\b" || true
  echo "IPv4 routes (table ${TABLE}):"
  ip -4 route show table "$TABLE" 2>/dev/null || true
  echo "----"
  echo "IPv6 rules (filtered):"
  ip -6 rule show | grep -E "lookup ${TABLE}\b" || true
  echo "IPv6 routes (table ${TABLE}):"
  ip -6 route show table "$TABLE" 2>/dev/null || true
}

cmd="${1:-}"
case "$cmd" in
  apply) apply_rules ;;
  remove) remove_rules ;;
  status) status ;;
  -h|--help|help|"") usage; exit 0 ;;
  *) echo "error: unknown command: $cmd" >&2; usage; exit 2 ;;
esac
