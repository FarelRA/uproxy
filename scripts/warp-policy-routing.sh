#!/usr/bin/env bash
#
# warp-policy-routing.sh - Policy routing for Cloudflare WARP by source address
#
# Usage: ./warp-policy-routing.sh {apply|remove|status|backup|restore} [source_addresses...]
#
# Environment variables:
#   IFACE       - WARP interface name (default: auto-detect or tun0)
#   TABLE       - Routing table number (default: 100)
#   PREF        - Rule preference/priority (default: 1000)
#   DRY_RUN     - Set to 1 for dry-run mode (default: 0)
#

set -euo pipefail

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BACKUP_FILE="$SCRIPT_DIR/.warp-routing-backup"

# Default configuration
IFACE="${IFACE:-}"
TABLE="${TABLE:-100}"
PREF="${PREF:-1000}"
DRY_RUN="${DRY_RUN:-0}"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
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

log_dry_run() {
    echo -e "${CYAN}[DRY-RUN]${NC} $*"
}

# Execute command (respects DRY_RUN)
execute() {
    if [[ "$DRY_RUN" == "1" ]]; then
        log_dry_run "$*"
        return 0
    else
        "$@"
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_info "Try: sudo $0 $*"
        exit 1
    fi
}

# Auto-detect WARP interface
detect_warp_interface() {
    local iface
    
    # Try common WARP interface names
    for iface in CloudflareWARP warp0 tun0; do
        if ip link show "$iface" &>/dev/null; then
            echo "$iface"
            return 0
        fi
    done
    
    # Try to find any tun interface
    iface=$(ip link show | grep -oP '^\d+: \K(tun\d+)' | head -n1 || true)
    if [[ -n "$iface" ]]; then
        echo "$iface"
        return 0
    fi
    
    return 1
}

# Validate interface exists
validate_interface() {
    local iface="$1"
    
    if ! ip link show "$iface" &>/dev/null; then
        log_error "Interface does not exist: $iface"
        log_info "Available interfaces:"
        ip -br link show | sed 's/^/  /'
        return 1
    fi
    
    return 0
}

# Get interface configuration
get_interface() {
    if [[ -z "$IFACE" ]]; then
        log_info "Auto-detecting WARP interface..."
        if IFACE=$(detect_warp_interface); then
            log_success "Detected WARP interface: $IFACE"
        else
            log_error "Could not auto-detect WARP interface"
            log_info "Please set IFACE environment variable"
            return 1
        fi
    fi
    
    validate_interface "$IFACE"
}

# Check if rule exists
rule_exists() {
    local from="$1"
    local table="$2"
    
    ip rule list | grep -q "from $from lookup $table"
}

# Check if IPv6 rule exists
rule6_exists() {
    local from="$1"
    local table="$2"
    
    ip -6 rule list | grep -q "from $from lookup $table"
}

# Add routing rule
add_rule() {
    local from="$1"
    local table="$2"
    local pref="$3"
    
    if rule_exists "$from" "$table"; then
        log_warn "IPv4 rule already exists: from $from lookup $table"
    else
        log_info "Adding IPv4 rule: from $from lookup $table (pref $pref)"
        execute ip rule add from "$from" table "$table" pref "$pref"
    fi
    
    # Try IPv6 if address looks like IPv6
    if [[ "$from" == *":"* ]]; then
        if rule6_exists "$from" "$table"; then
            log_warn "IPv6 rule already exists: from $from lookup $table"
        else
            log_info "Adding IPv6 rule: from $from lookup $table (pref $pref)"
            execute ip -6 rule add from "$from" table "$table" pref "$pref"
        fi
    fi
}

# Remove routing rule
remove_rule() {
    local from="$1"
    local table="$2"
    
    if rule_exists "$from" "$table"; then
        log_info "Removing IPv4 rule: from $from lookup $table"
        execute ip rule del from "$from" table "$table"
    else
        log_warn "IPv4 rule does not exist: from $from lookup $table"
    fi
    
    # Try IPv6 if address looks like IPv6
    if [[ "$from" == *":"* ]]; then
        if rule6_exists "$from" "$table"; then
            log_info "Removing IPv6 rule: from $from lookup $table"
            execute ip -6 rule del from "$from" table "$table"
        else
            log_warn "IPv6 rule does not exist: from $from lookup $table"
        fi
    fi
}

# Setup routing table
setup_table() {
    local iface="$1"
    local table="$2"
    
    log_info "Setting up routing table $table for interface $iface"
    
    # Add default route via interface
    if ip route show table "$table" | grep -q "default"; then
        log_warn "Default route already exists in table $table"
    else
        log_info "Adding default route to table $table via $iface"
        execute ip route add default dev "$iface" table "$table"
    fi
    
    # Try IPv6
    if ip -6 route show table "$table" | grep -q "default"; then
        log_warn "IPv6 default route already exists in table $table"
    else
        log_info "Adding IPv6 default route to table $table via $iface"
        execute ip -6 route add default dev "$iface" table "$table" 2>/dev/null || log_warn "IPv6 not available"
    fi
}

# Apply policy routing
apply_routing() {
    local sources=("$@")
    
    if [[ ${#sources[@]} -eq 0 ]]; then
        log_error "No source addresses specified"
        log_info "Usage: $0 apply <source_address> [<source_address>...]"
        return 1
    fi
    
    check_root
    get_interface || return 1
    
    log_info "Applying policy routing for WARP interface: $IFACE"
    log_info "Routing table: $TABLE"
    log_info "Rule preference: $PREF"
    
    # Setup routing table
    setup_table "$IFACE" "$TABLE"
    
    # Add rules for each source
    for source in "${sources[@]}"; do
        add_rule "$source" "$TABLE" "$PREF"
    done
    
    # Flush route cache
    if [[ "$DRY_RUN" != "1" ]]; then
        ip route flush cache 2>/dev/null || true
    fi
    
    log_success "Policy routing applied successfully"
    
    # Save configuration for backup
    if [[ "$DRY_RUN" != "1" ]]; then
        save_backup "${sources[@]}"
    fi
}

# Remove policy routing
remove_routing() {
    local sources=("$@")
    
    if [[ ${#sources[@]} -eq 0 ]]; then
        log_error "No source addresses specified"
        log_info "Usage: $0 remove <source_address> [<source_address>...]"
        return 1
    fi
    
    check_root
    
    log_info "Removing policy routing rules"
    log_info "Routing table: $TABLE"
    
    # Remove rules for each source
    for source in "${sources[@]}"; do
        remove_rule "$source" "$TABLE"
    done
    
    # Flush route cache
    if [[ "$DRY_RUN" != "1" ]]; then
        ip route flush cache 2>/dev/null || true
    fi
    
    log_success "Policy routing rules removed successfully"
}

# Show routing status
show_status() {
    log_info "Policy Routing Status"
    echo ""
    
    # Show interface
    if [[ -n "$IFACE" ]]; then
        echo -e "${CYAN}Interface:${NC} $IFACE"
        if validate_interface "$IFACE" 2>/dev/null; then
            echo -e "${GREEN}  Status: UP${NC}"
        else
            echo -e "${RED}  Status: DOWN${NC}"
        fi
    else
        if IFACE=$(detect_warp_interface 2>/dev/null); then
            echo -e "${CYAN}Interface:${NC} $IFACE (auto-detected)"
        else
            echo -e "${RED}Interface: Not detected${NC}"
        fi
    fi
    
    echo ""
    echo -e "${CYAN}Routing Table:${NC} $TABLE"
    echo -e "${CYAN}Rule Preference:${NC} $PREF"
    echo ""
    
    # Show routing table contents
    echo -e "${CYAN}Routes in table $TABLE:${NC}"
    if ip route show table "$TABLE" 2>/dev/null | grep -q .; then
        ip route show table "$TABLE" | sed 's/^/  /'
    else
        echo "  (empty)"
    fi
    echo ""
    
    # Show IPv6 routes
    echo -e "${CYAN}IPv6 routes in table $TABLE:${NC}"
    if ip -6 route show table "$TABLE" 2>/dev/null | grep -q .; then
        ip -6 route show table "$TABLE" | sed 's/^/  /'
    else
        echo "  (empty)"
    fi
    echo ""
    
    # Show policy rules
    echo -e "${CYAN}Policy rules for table $TABLE:${NC}"
    if ip rule list | grep "lookup $TABLE" | grep -q .; then
        ip rule list | grep "lookup $TABLE" | sed 's/^/  /'
    else
        echo "  (none)"
    fi
    echo ""
    
    # Show IPv6 policy rules
    echo -e "${CYAN}IPv6 policy rules for table $TABLE:${NC}"
    if ip -6 rule list | grep "lookup $TABLE" 2>/dev/null | grep -q .; then
        ip -6 rule list | grep "lookup $TABLE" | sed 's/^/  /'
    else
        echo "  (none)"
    fi
    echo ""
    
    # Show backup status
    if [[ -f "$BACKUP_FILE" ]]; then
        echo -e "${CYAN}Backup:${NC} Available at $BACKUP_FILE"
    else
        echo -e "${YELLOW}Backup:${NC} Not available"
    fi
}

# Save backup
save_backup() {
    local sources=("$@")
    
    log_info "Saving configuration backup to $BACKUP_FILE"
    
    cat > "$BACKUP_FILE" <<EOF
# WARP Policy Routing Backup
# Generated: $(date)
IFACE=$IFACE
TABLE=$TABLE
PREF=$PREF
SOURCES=(${sources[*]})
EOF
    
    log_success "Backup saved"
}

# Restore from backup
restore_backup() {
    if [[ ! -f "$BACKUP_FILE" ]]; then
        log_error "Backup file not found: $BACKUP_FILE"
        return 1
    fi
    
    log_info "Restoring configuration from backup..."
    
    # Source the backup file
    # shellcheck disable=SC1090
    source "$BACKUP_FILE"
    
    log_info "Backup configuration:"
    log_info "  Interface: $IFACE"
    log_info "  Table: $TABLE"
    log_info "  Preference: $PREF"
    log_info "  Sources: ${SOURCES[*]}"
    
    # Apply the configuration
    apply_routing "${SOURCES[@]}"
}

# Show usage
show_usage() {
    cat <<EOF
Usage: $0 {apply|remove|status|backup|restore} [options]

Commands:
    apply <sources...>   Apply policy routing for source addresses
    remove <sources...>  Remove policy routing for source addresses
    status               Show current routing status
    backup               Save current configuration
    restore              Restore configuration from backup

Environment Variables:
    IFACE       WARP interface name (default: auto-detect)
    TABLE       Routing table number (default: 100)
    PREF        Rule preference/priority (default: 1000)
    DRY_RUN     Set to 1 for dry-run mode (default: 0)

Examples:
    # Apply routing for single source
    sudo $0 apply 192.168.1.100

    # Apply routing for multiple sources
    sudo $0 apply 192.168.1.100 192.168.1.101 10.0.0.0/24

    # Apply with custom interface
    sudo IFACE=warp0 $0 apply 192.168.1.100

    # Dry-run mode (test without making changes)
    sudo DRY_RUN=1 $0 apply 192.168.1.100

    # Remove routing
    sudo $0 remove 192.168.1.100

    # Show status
    $0 status

    # Backup and restore
    sudo $0 apply 192.168.1.100  # This auto-saves backup
    sudo $0 restore               # Restore from backup

EOF
}

# Main
main() {
    local command="${1:-}"
    shift || true
    
    if [[ -z "$command" ]]; then
        show_usage
        exit 1
    fi
    
    case "$command" in
        apply)
            apply_routing "$@"
            ;;
        remove)
            remove_routing "$@"
            ;;
        status)
            show_status
            ;;
        backup)
            if [[ $# -eq 0 ]]; then
                log_error "No sources specified for backup"
                exit 1
            fi
            save_backup "$@"
            ;;
        restore)
            restore_backup
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
