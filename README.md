# Luks_storage
## LUKS Web Manager (Rust Edition)

A modern, secure, and self-hosted web interface for managing LUKS (Linux Unified Key Setup) encrypted drives, written in Rust. This application provides a clean UI to unlock, mount, browse files, and lock your encrypted storage remotely.

---

### Core Features

- **Secure User Management:** User accounts are stored in a local SQLite database with securely hashed passwords using Argon2.
- **Session Management:** Persistent login sessions using secure, signed cookies.
- **Remote LUKS Control:** Unlock, mount, and lock your LUKS device through the web interface.
- **Real-time System State:** The application checks the actual mount status on startup to keep the UI in sync with the system.
- **Dynamic UI:** The interface changes based on whether the drive is locked or unlocked.
- **File Browser:** Navigate the directory structure of the mounted drive.
- **File Operations:**
    - Create new folders
    - Rename files and folders
    - Delete files and folders
    - Preview common file types (images, text, PDFs) in an overlay
    - Download files
- **Admin Panel:** A dedicated section for administrators to manage user accounts (Create, List, Delete).

---

### Prerequisites

Before you begin, ensure you have the following installed on your server:

- **Rust:** The application is built with Rust. Install it using rustup.
    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
- **build-essential:** Required for compiling Rust and some of its dependencies.
    ```sh
    sudo apt update
    sudo apt install -y build-essential
    ```
- **sqlx-cli:** A command-line tool for managing the application's database.
    ```sh
    cargo install sqlx-cli
    ```
- **cryptsetup:** The underlying utility for managing LUKS volumes.
    ```sh
    sudo apt install -y cryptsetup
    ```

---

### 1. Initial Setup

#### Database Setup

The application uses a local SQLite database (`luks_manager.db`) to store user information.

- **Create the Database File:**
    ```sh
    sqlx database create --database-url sqlite:luks_manager.db
    ```

- **Create the Database Schema (Migration):**
    ```sh
    sqlx migrate add create_users_table
    ```
    Open the generated `.sql` file in the `migrations/` directory and add:
    ```sql
    CREATE TABLE users (
            id INTEGER PRIMARY KEY NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
    );
    ```

- **Run the Migration:**
    ```sh
    sqlx migrate run --database-url sqlite:luks_manager.db
    ```

#### Sudoers Configuration

For the application to run LUKS commands without asking for a password, configure sudoers:

- Open the sudoers file:
    ```sh
    sudo visudo
    ```
- Add (replace `your_username` with the user running the app):
    ```
    your_username ALL=(ALL) NOPASSWD: /usr/sbin/cryptsetup, /usr/bin/mount, /usr/bin/umount, /usr/bin/chown
    ```

---

### 2. Configuration

Set environment variables in your shell or a `.env` file in the project root:

```env
# The path to your LUKS encrypted device or partition
LUKS_DEVICE_PATH=/dev/sdX1

# The name for the device mapper
LUKS_MAPPER_NAME=luks_web_mapper

# The directory where the device will be mounted
LUKS_MOUNT_POINT=/mnt/luks_drive

# The path to the SQLite database file
DATABASE_URL=sqlite:luks_manager.db
```

---

### 3. Running the Application

Run the application:

```sh
cargo run
```

The application will be available at [http://127.0.0.1:8080](http://127.0.0.1:8080).

---

### Default Admin User

On the first run, if the database is empty, a default admin user is created:

- **Username:** `admin`
- **Password:** `password`

> **Important:** Log in and change this password immediately.