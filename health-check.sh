#!/bin/bash
# ===================================
# LUKS Web Manager Health Check Script
# ===================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

DATABASE_URL="${DATABASE_URL:-sqlite:luks_manager.db}"
LUKS_MOUNT_POINT="${LUKS_MOUNT_POINT:-/tmp/luks_test}"
SERVER_PORT="${SERVER_PORT:-8081}"

log_info "LUKS Web Manager Health Check"
echo "======================================"

# Check if project files exist
if [[ -f "Cargo.toml" ]]; then
    log_success "Project files found"
else
    log_error "Project files missing"
fi

# Check Rust installation
if command -v cargo &> /dev/null; then
    RUST_VERSION=$(rustc --version)
    log_success "Rust installed: $RUST_VERSION"
else
    log_error "Rust not installed"
fi

# Check database
DATABASE_FILE="${DATABASE_URL#sqlite:}"
if [[ -f "$DATABASE_FILE" ]]; then
    log_success "Database file exists: $DATABASE_FILE"
    
    if command -v sqlite3 &> /dev/null; then
        USER_COUNT=$(sqlite3 "$DATABASE_FILE" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "0")
        log_info "Users in database: $USER_COUNT"
    fi
else
    log_warning "Database file not found: $DATABASE_FILE"
fi

# Check mount point
if [[ -d "$LUKS_MOUNT_POINT" ]]; then
    log_success "Mount point exists: $LUKS_MOUNT_POINT"
else
    log_warning "Mount point missing: $LUKS_MOUNT_POINT"
fi

# Check if server is running
if netstat -tuln 2>/dev/null | grep ":$SERVER_PORT " &>/dev/null; then
    log_success "Server is running on port $SERVER_PORT"
    
    # Test HTTP connectivity
    if command -v curl &> /dev/null; then
        if curl -s "http://127.0.0.1:$SERVER_PORT" &>/dev/null; then
            log_success "Server is responding to HTTP requests"
        else
            log_warning "Server is not responding to HTTP requests"
        fi
    fi
else
    log_warning "Server is not running on port $SERVER_PORT"
fi

# Check system dependencies
if command -v cryptsetup &> /dev/null; then
    log_success "cryptsetup is installed"
else
    log_warning "cryptsetup not found (required for LUKS operations)"
fi

# Check logs
if [[ -d "logs" ]]; then
    log_success "Logs directory exists"
    if [[ -f "logs/server.log" ]]; then
        LOG_SIZE=$(wc -l < logs/server.log)
        log_info "Server log has $LOG_SIZE lines"
    fi
else
    log_info "No logs directory found"
fi

echo "======================================"
log_info "Health check completed"
