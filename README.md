# LUKS Web Manager (Enhanced Edition)

A modern, secure, and feature-rich self-hosted web interface for managing LUKS (Linux Unified Key Setup) encrypted drives, written in Rust. This application provides a clean, responsive UI to unlock, mount, browse files, and manage your encrypted storage remotely with advanced file management capabilities.

## ✨ New Features & Enhancements

### 🎨 **Modern User Interface**
- **Clean, Minimal Design**: Intuitive and professional interface
- **Responsive Layout**: Optimized for mobile, tablet, and desktop
- **Dark/Light Mode Toggle**: Switch themes with persistent preference storage
- **Bootstrap 5 Integration**: Modern UI components and icons
- **Touch-Friendly Mobile UI**: Enhanced mobile experience

### 🗂️ **Advanced File Management**
- **Drag-and-Drop Upload**: Visual drop zone with progress indicators
- **Multi-File Operations**: Select multiple files for batch actions
- **Right-Click Context Menu**: Quick access to file operations
- **Advanced Search**: Real-time file filtering and search
- **List/Grid View Toggle**: Multiple viewing options
- **File Type Icons**: Visual file type identification
- **Breadcrumb Navigation**: Easy directory traversal

### 📁 **File Operations**
- **Batch Actions**: Move, delete, download multiple files
- **File Preview**: Inline previews for images, text, and documents
- **Download Management**: Single and multi-file downloads
- **Folder Management**: Create, rename, and organize folders
- **Quick Search**: Instant file and folder search
- **Keyboard Shortcuts**: Ctrl+A (select all), Delete key support

### ⚡ **Performance Optimizations**
- **Offline Operation**: All assets served locally (no internet required)
- **Fast Loading**: Optimized for older hardware
- **Minimal Animations**: Disabled expensive transitions for better performance
- **Efficient DOM Handling**: Optimized JavaScript for smooth operation
- **Local Static Assets**: Bootstrap, icons, and scripts bundled locally

### 🔒 **Security Features**
- **Secure User Management**: Argon2 password hashing
- **Session Management**: Persistent login with secure cookies
- **Access Control**: Role-based permissions (admin/user)
- **File Access Protection**: Path traversal protection
- **Secure Authentication**: Strong password requirements

---

## 🚀 Core Features

### **LUKS Device Management**
- **Remote LUKS Control**: Unlock, mount, and lock encrypted devices
- **Real-time Status**: Live mount status monitoring
- **Automatic Detection**: Checks system mount state on startup
- **Secure Password Input**: Protected LUKS password entry

### **File Browser**
- **Directory Navigation**: Browse mounted drive contents
- **File Operations**: Create, rename, delete, move files and folders
- **File Downloads**: Direct file download capability
- **File Previews**: View files without downloading
- **Upload Support**: Drag-and-drop file uploads

### **Admin Panel**
- **User Management**: Create, list, and delete user accounts
- **Role Management**: Admin and user role assignments
- **System Overview**: Device and mount point information

---

## 📋 Prerequisites

Before you begin, ensure you have the following installed on your server:

### **System Requirements**
- **Operating System**: Linux (Ubuntu/Debian recommended)
- **Hardware**: Minimum 512MB RAM, works on older hardware
- **Network**: Can operate offline after initial setup

### **Dependencies**
- **Rust**: Install using rustup
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source ~/.cargo/env
    ```
- **Build Tools**: Required for compilation
    ```bash
    sudo apt update
    sudo apt install -y build-essential pkg-config libssl-dev
    ```
- **SQLx CLI**: Database management tool
    ```bash
    cargo install sqlx-cli --no-default-features --features sqlite
    ```
- **LUKS Tools**: Encryption utilities
    ```bash
    sudo apt install -y cryptsetup
    ```

---

## 🛠️ Installation & Setup

### **1. Clone & Build**
```bash
git clone <your-repository-url>
cd Luks_storage
cargo build --release
```

### **2. Database Setup**
```bash
# Create database
sqlx database create --database-url sqlite:luks_manager.db

# Run migrations
sqlx migrate run --database-url sqlite:luks_manager.db
```

### **3. System Configuration**

#### **Configure Sudoers** (Required for LUKS operations)
```bash
sudo visudo
```
Add the following line (replace `your_username` with your actual username):
```
your_username ALL=(ALL) NOPASSWD: /usr/sbin/cryptsetup, /usr/bin/mount, /usr/bin/umount, /usr/bin/chown
```

#### **Environment Variables**
Create a `.env` file or set environment variables:
```env
# LUKS Device Configuration
LUKS_DEVICE_PATH=/dev/sdX1
LUKS_MAPPER_NAME=luks_web_mapper
LUKS_MOUNT_POINT=/mnt/luks_drive

# Database Configuration
DATABASE_URL=sqlite:luks_manager.db

# Server Configuration (optional)
RUST_LOG=info
```

### **4. Static Assets** (Already included)
The application now includes all static assets locally:
- Bootstrap CSS & JS
- Bootstrap Icons
- Custom optimizations

---

## 🚀 Running the Application

### **Development Mode**
```bash
RUST_LOG=info cargo run
```

### **Production Mode**
```bash
cargo build --release
RUST_LOG=warn ./target/release/luks_web_manager
```

### **Background Service**
```bash
nohup ./target/release/luks_web_manager > luks_manager.log 2>&1 &
```

The application will be available at: **http://127.0.0.1:8080**

---

## 👤 Default Credentials

On first run, a default admin user is automatically created:
- **Username**: `admin`
- **Password**: `password`

> ⚠️ **Important**: Change this password immediately after first login!

---

## 🎮 Usage Guide

### **Unlocking Your Device**
1. Access the web interface
2. Log in with your credentials
3. Enter your LUKS password in the sidebar
4. Click "Unlock & Mount"

### **File Management**
- **Upload Files**: Drag files onto the page or use the Upload button
- **Select Multiple Files**: Use checkboxes for batch operations
- **Search Files**: Use the search bar for quick filtering
- **Navigation**: Click folders to navigate, use breadcrumbs to go back
- **Preview Files**: Click the eye icon to preview files
- **Download Files**: Click download icon or select multiple for batch download

### **Keyboard Shortcuts**
- **Ctrl+A**: Select all files
- **Delete**: Delete selected files (with confirmation)
- **Escape**: Clear selection

### **Mobile Usage**
- Touch-friendly interface
- Responsive design adapts to screen size
- Swipe gestures supported
- Mobile-optimized file operations

---

## 🔧 Configuration Options

### **Performance Tuning**
The application is optimized for older hardware:
- Animations disabled for better performance
- Efficient DOM handling
- Minimal resource usage
- Fast loading times

### **Customization**
- **Themes**: Light/Dark mode toggle
- **Layout**: List/Grid view options
- **File Display**: Customizable file type icons

---

## 📂 Project Structure

```
Luks_storage/
├── src/
│   └── main.rs              # Main application code
├── templates/
│   ├── base.html            # Base template with modern UI
│   ├── index.html           # Enhanced file browser
│   ├── login.html           # Login interface
│   ├── admin_users.html     # User management
│   └── admin_user_form.html # User creation form
├── static/                  # Local static assets
│   ├── css/
│   │   ├── bootstrap.min.css
│   │   ├── bootstrap-icons.css
│   │   └── custom.css       # Performance optimizations
│   └── js/
│       └── bootstrap.bundle.min.js
├── migrations/              # Database migrations
├── Cargo.toml              # Dependencies
└── README.md               # This file
```

---

## 🛡️ Security Considerations

### **Network Security**
- Use HTTPS in production (reverse proxy recommended)
- Firewall configuration to restrict access
- VPN access for remote connections

### **File Security**
- Regular backups of encrypted data
- Strong LUKS passwords
- Secure key management

### **Application Security**
- Regular password changes
- User access monitoring
- Log file monitoring

---

## 🚀 Performance Features

### **Offline Operation**
- All assets served locally
- No external dependencies
- Works without internet connection

### **Optimized for Older Hardware**
- Minimal system resource usage
- Fast loading times
- Efficient memory management
- Disabled expensive animations

### **Mobile Optimization**
- Touch-friendly interface
- Responsive design
- Optimized for mobile browsers

---

## 🛠️ Troubleshooting

### **Common Issues**

#### **Permission Denied Errors**
```bash
# Check sudoers configuration
sudo visudo

# Verify device permissions
ls -la /dev/your-device
```

#### **Database Connection Issues**
```bash
# Recreate database if corrupted
rm luks_manager.db
sqlx database create --database-url sqlite:luks_manager.db
sqlx migrate run --database-url sqlite:luks_manager.db
```

#### **Static Assets Not Loading**
```bash
# Verify static files exist
ls -la static/css/
ls -la static/js/

# Re-download if missing
curl -o static/css/bootstrap.min.css https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css
```

### **Performance Issues**
- Ensure adequate RAM (minimum 512MB)
- Check disk space on mount point
- Monitor system logs for errors

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.

### **Development Setup**
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

## 📄 License

This project is open source. Please check the license file for details.

---

## 🎯 Roadmap

### **Planned Features**
- [ ] File versioning and rollback
- [ ] ZIP/TAR archive support
- [ ] Online document editing
- [ ] Real-time file sync
- [ ] Advanced user permissions
- [ ] API endpoints for automation
- [ ] Backup and restore functionality
- [ ] Multi-language support

### **Performance Improvements**
- [ ] Virtual scrolling for large directories
- [ ] Background file operations
- [ ] Caching optimizations
- [ ] Database performance tuning

---

## 📞 Support

If you encounter any issues or have questions:
1. Check the troubleshooting section
2. Review the logs for error messages
3. Ensure all prerequisites are installed
4. Verify LUKS device configuration

---

**Enjoy your secure, fast, and modern LUKS file management experience!** 🔒✨
