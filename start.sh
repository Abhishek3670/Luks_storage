#!/bin/bash
# ===================================
# LUKS Web Manager Quick Start Script
# ===================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Configuration
DATABASE_URL="${DATABASE_URL:-sqlite:luks_manager.db}"
LUKS_MOUNT_POINT="${LUKS_MOUNT_POINT:-/tmp/luks_test}"
RUST_LOG="${RUST_LOG:-info}"

# Export environment variables
export DATABASE_URL LUKS_MOUNT_POINT RUST_LOG

# Find the binary
if [[ -f "./target/release/luks_web_manager" ]]; then
    BINARY="./target/release/luks_web_manager"
elif [[ -f "./target/debug/luks_web_manager" ]]; then
    BINARY="./target/debug/luks_web_manager"
else
    log_info "No binary found, running full initialization..."
    exec ./init.sh
fi

# Quick checks
if [[ ! -f "${DATABASE_URL#sqlite:}" ]]; then
    log_info "Database missing, running full initialization..."
    exec ./init.sh
fi

# Create logs directory if needed
mkdir -p logs

log_success "Starting LUKS Web Manager..."
log_info "Binary: $BINARY"
log_info "Database: $DATABASE_URL"
log_info "Mount point: $LUKS_MOUNT_POINT"
log_info ""
log_info "Server starting - check logs/server.log for details"
log_info "Press Ctrl+C to stop"

# Start server with logging
exec $BINARY 2>&1 | tee -a logs/server.log
