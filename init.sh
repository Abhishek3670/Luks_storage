#!/bin/bash
# ===================================
# LUKS Web Manager Initialization Script
# ===================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration variables with defaults
PROJECT_NAME="LUKS Web Manager"
DATABASE_URL="${DATABASE_URL:-sqlite:luks_manager.db}"
LUKS_MOUNT_POINT="${LUKS_MOUNT_POINT:-/tmp/luks_test}"
LUKS_DEVICE_PATH="${LUKS_DEVICE_PATH:-/dev/sdb1}"
LUKS_MAPPER_NAME="${LUKS_MAPPER_NAME:-encrypted_volume}"
RUST_LOG="${RUST_LOG:-info}"
SERVER_PORT="${SERVER_PORT:-8081}"

# ===================================
# Pre-flight Checks
# ===================================

log_info "Starting $PROJECT_NAME initialization..."

# Check if we're in the right directory
if [[ ! -f "Cargo.toml" ]]; then
    log_error "Cargo.toml not found! Please run this script from the project root directory."
    exit 1
fi

if [[ ! -f "src/main.rs" ]]; then
    log_error "src/main.rs not found! Please ensure you're in the LUKS Web Manager project directory."
    exit 1
fi

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    log_error "Cargo/Rust not found! Please install Rust first:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Check if SQLite is available for debugging
if ! command -v sqlite3 &> /dev/null; then
    log_warning "sqlite3 command not found. Database debugging may be limited."
fi

log_success "Pre-flight checks passed!"

# ===================================
# Environment Setup
# ===================================

log_info "Setting up environment variables..."

export DATABASE_URL="$DATABASE_URL"
export LUKS_MOUNT_POINT="$LUKS_MOUNT_POINT"
export LUKS_DEVICE_PATH="$LUKS_DEVICE_PATH"
export LUKS_MAPPER_NAME="$LUKS_MAPPER_NAME"
export RUST_LOG="$RUST_LOG"

log_info "Environment Configuration:"
echo "  DATABASE_URL: $DATABASE_URL"
echo "  LUKS_MOUNT_POINT: $LUKS_MOUNT_POINT"
echo "  LUKS_DEVICE_PATH: $LUKS_DEVICE_PATH"
echo "  LUKS_MAPPER_NAME: $LUKS_MAPPER_NAME"
echo "  SERVER_PORT: $SERVER_PORT"
echo "  RUST_LOG: $RUST_LOG"

# ===================================
# Directory Setup
# ===================================

log_info "Creating necessary directories..."

# Create mount point directory if it doesn't exist
if [[ ! -d "$LUKS_MOUNT_POINT" ]]; then
    mkdir -p "$LUKS_MOUNT_POINT"
    log_success "Created mount point directory: $LUKS_MOUNT_POINT"
else
    log_info "Mount point directory already exists: $LUKS_MOUNT_POINT"
fi

# Create logs directory
if [[ ! -d "logs" ]]; then
    mkdir -p logs
    log_success "Created logs directory"
fi

# ===================================
# Database Setup
# ===================================

log_info "Setting up database..."

DATABASE_FILE="${DATABASE_URL#sqlite:}"

# Remove any existing corrupted database files
if [[ -f "$DATABASE_FILE-shm" ]] || [[ -f "$DATABASE_FILE-wal" ]]; then
    log_warning "Found SQLite WAL/SHM files, cleaning up..."
    rm -f "$DATABASE_FILE-shm" "$DATABASE_FILE-wal"
fi

# Check if database file exists and is accessible
if [[ -f "$DATABASE_FILE" ]]; then
    log_info "Database file exists: $DATABASE_FILE"
    
    # Test database connectivity
    if command -v sqlite3 &> /dev/null; then
        if sqlite3 "$DATABASE_FILE" ".tables" &>/dev/null; then
            log_success "Database file is accessible"
        else
            log_warning "Database file appears corrupted, will recreate"
            rm -f "$DATABASE_FILE"
        fi
    fi
else
    log_info "Database file does not exist, will be created automatically"
    # Create empty database file to ensure proper permissions
    touch "$DATABASE_FILE"
fi

# ===================================
# Application Build
# ===================================

log_info "Building application..."

if cargo build --release; then
    log_success "Application built successfully!"
    BINARY_PATH="./target/release/luks_web_manager"
else
    log_warning "Release build failed, trying debug build..."
    if cargo build; then
        log_success "Debug build successful!"
        BINARY_PATH="./target/debug/luks_web_manager"
    else
        log_error "Build failed! Please check the error messages above."
        exit 1
    fi
fi

# ===================================
# Port Availability Check
# ===================================

log_info "Checking port availability..."

if netstat -tuln 2>/dev/null | grep ":$SERVER_PORT " &>/dev/null; then
    log_warning "Port $SERVER_PORT is already in use!"
    
    # Try to find an available port
    for port in {8082..8090}; do
        if ! netstat -tuln 2>/dev/null | grep ":$port " &>/dev/null; then
            SERVER_PORT=$port
            log_info "Using alternative port: $SERVER_PORT"
            
            # Update the port in source code
            sed -i "s/8081/$SERVER_PORT/g" src/main.rs
            
            # Rebuild with new port
            log_info "Rebuilding with new port..."
            cargo build --release &>/dev/null || cargo build &>/dev/null
            break
        fi
    done
fi

# ===================================
# System Dependencies Check
# ===================================

log_info "Checking system dependencies..."

# Check for cryptsetup (required for LUKS operations)
if ! command -v cryptsetup &> /dev/null; then
    log_warning "cryptsetup not found! LUKS operations may fail."
    log_info "To install: sudo apt-get install cryptsetup-bin"
fi

# Check for sudo access (needed for LUKS operations)
if ! sudo -n true 2>/dev/null; then
    log_warning "Passwordless sudo not configured. LUKS operations may prompt for password."
fi

# ===================================
# Application Startup
# ===================================

log_info "Starting $PROJECT_NAME server..."
log_info "Server will be available at: http://127.0.0.1:$SERVER_PORT"
log_info "Default login: admin / password"
log_info ""
log_info "Press Ctrl+C to stop the server"
log_info "Logs will be saved to: logs/server.log"

# Create startup timestamp
echo "=== Server started at $(date) ===" >> logs/server.log

# Start the server with proper logging
exec $BINARY_PATH 2>&1 | tee -a logs/server.log

