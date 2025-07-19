#!/bin/bash
# ===================================
# LUKS Web Manager Cleanup Script
# ===================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

DATABASE_URL="${DATABASE_URL:-sqlite:luks_manager.db}"
LUKS_MOUNT_POINT="${LUKS_MOUNT_POINT:-/tmp/luks_test}"
SERVER_PORT="${SERVER_PORT:-8081}"

log_info "LUKS Web Manager Cleanup"
echo "======================================"

# Stop running server
if netstat -tuln 2>/dev/null | grep ":$SERVER_PORT " &>/dev/null; then
    log_info "Stopping server on port $SERVER_PORT..."
    pkill -f luks_web_manager || true
    sleep 2
    log_success "Server stopped"
else
    log_info "No server running on port $SERVER_PORT"
fi

# Clean up database files
DATABASE_FILE="${DATABASE_URL#sqlite:}"
if [[ -f "$DATABASE_FILE" ]] || [[ -f "$DATABASE_FILE-shm" ]] || [[ -f "$DATABASE_FILE-wal" ]]; then
    read -p "Remove database files? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "$DATABASE_FILE" "$DATABASE_FILE-shm" "$DATABASE_FILE-wal"
        log_success "Database files removed"
    else
        log_info "Database files kept"
    fi
fi

# Clean up build artifacts
if [[ -d "target" ]]; then
    read -p "Remove build artifacts (target/)? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf target/
        log_success "Build artifacts removed"
    else
        log_info "Build artifacts kept"
    fi
fi

# Clean up test mount point
if [[ -d "$LUKS_MOUNT_POINT" ]] && [[ "$LUKS_MOUNT_POINT" == /tmp/* ]]; then
    read -p "Remove test mount point ($LUKS_MOUNT_POINT)? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rmdir "$LUKS_MOUNT_POINT" 2>/dev/null || rm -rf "$LUKS_MOUNT_POINT"
        log_success "Test mount point removed"
    else
        log_info "Mount point kept"
    fi
fi

# Clean up logs
if [[ -d "logs" ]]; then
    read -p "Remove log files? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf logs/
        log_success "Log files removed"
    else
        log_info "Log files kept"
    fi
fi

echo "======================================"
log_success "Cleanup completed"
