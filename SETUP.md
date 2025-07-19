# 🚀 LUKS Web Manager - Setup Guide

This guide will help you get the LUKS Web Manager up and running with zero configuration hassle.

## 📁 Available Scripts

### `init.sh` - Complete Setup & Start
The main initialization script that handles everything:
- ✅ Pre-flight checks (Rust, project files)
- ✅ Database setup and migration
- ✅ Directory creation
- ✅ Application building
- ✅ Port availability checking
- ✅ Server startup with logging

### `health-check.sh` - System Status
Quick health check to verify everything is working:
- ✅ Project files
- ✅ Rust installation
- ✅ Database status
- ✅ Server status
- ✅ System dependencies

### `cleanup.sh` - Clean Environment
Removes generated files and stops services:
- 🗑️ Stop running server
- 🗑️ Remove database files (optional)
- 🗑️ Remove build artifacts (optional)
- 🗑️ Remove logs (optional)

## 🏁 Quick Start

1. **Initialize and Start**:
   ```bash
   ./init.sh
   ```

2. **Check Status** (in another terminal):
   ```bash
   ./health-check.sh
   ```

3. **Access Web Interface**:
   - URL: `http://127.0.0.1:8081` (or shown port)
   - Username: `admin`
   - Password: `password`

## ⚙️ Configuration Options

You can customize the setup using environment variables:

```bash
export DATABASE_URL="sqlite:custom_db.db"
export LUKS_MOUNT_POINT="/custom/mount/path"
export LUKS_DEVICE_PATH="/dev/sdc1"
export LUKS_MAPPER_NAME="my_encrypted_volume"
export SERVER_PORT="9000"
export RUST_LOG="debug"

./init.sh
```

## 📋 What the Init Script Does

### 1. Pre-flight Checks
- Verifies Rust/Cargo installation
- Checks for required project files
- Validates directory structure

### 2. Environment Setup
- Sets default configuration values
- Creates necessary directories
- Sets up logging

### 3. Database Initialization
- Creates SQLite database if missing
- Handles corrupted database cleanup
- Runs database migrations
- Creates default admin user

### 4. Application Build
- Attempts release build first
- Falls back to debug build if needed
- Updates binary path accordingly

### 5. Port Management
- Checks if default port is available
- Finds alternative port if needed
- Updates source code with new port
- Rebuilds if port changed

### 6. Server Startup
- Starts the web server
- Enables logging to file
- Displays access information

## 🔧 Troubleshooting

### Database Issues
```bash
# Remove corrupted database and restart
rm -f luks_manager.db*
./init.sh
```

### Port Conflicts
```bash
# Use custom port
export SERVER_PORT=9090
./init.sh
```

### Build Failures
```bash
# Check Rust installation
rustc --version
cargo --version

# Update Rust if needed
rustup update
```

### Permission Issues
```bash
# Ensure scripts are executable
chmod +x init.sh health-check.sh cleanup.sh

# For LUKS operations, ensure sudo access
sudo -v
```

## 📊 Log Files

Logs are automatically saved to:
- `logs/server.log` - Server output and errors
- Application logs include timestamps and log levels

## 🛡️ Security Notes

- Default credentials: `admin` / `password` - **Change immediately in production!**
- The server binds to `127.0.0.1` (localhost only)
- For production use, consider:
  - Changing default passwords
  - Setting up HTTPS proxy (nginx/apache)
  - Configuring firewall rules
  - Using proper LUKS device paths

## 🔄 Development Workflow

```bash
# Start development
./init.sh

# Check status
./health-check.sh

# Make changes to code...

# Restart with changes
pkill luks_web_manager
./init.sh

# Clean up when done
./cleanup.sh
```

## 📞 Support

If you encounter issues:

1. Run health check: `./health-check.sh`
2. Check logs: `tail -f logs/server.log`
3. Try cleanup and restart: `./cleanup.sh && ./init.sh`

---

**Happy LUKS managing! 🔐**
