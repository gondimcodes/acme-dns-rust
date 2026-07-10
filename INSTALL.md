# Installation & Compilation Guide

This document details how to compile, configure, and install both the `acme-dns-rust` server and the `acme-dns-client-rust` client.

---

## Prerequisites: Installing Rust and Cargo

Both the server and the client require the Rust toolchain to compile from source. The recommended way to install it is via **rustup**.

### Linux (Debian/Ubuntu)
```bash
# Install system build dependencies
sudo apt-get update
sudo apt-get install -y curl build-essential pkg-config libssl-dev libsqlite3-dev

# Install rustup (installs Rust + Cargo)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Load Cargo into the current shell session
source $HOME/.cargo/env

# Verify installation
rustc --version
cargo --version
```

### FreeBSD
```bash
# Install Rust and Cargo via pkg (includes cargo)
pkg install -y rust

# Verify installation
rustc --version
cargo --version
```

> **Note:** After installation, open a new terminal session or run `source $HOME/.cargo/env` to ensure `cargo` is available in your `PATH`.

---

# SECTION 1: acme-dns-rust (The Server)

## 1. Compilation
Build the production binary in release mode:
```bash
cargo build --release
```
The optimized executable will be generated at `./target/release/acme-dns-rust`.

Copy the binary to the standard executable path:
```bash
sudo cp ./target/release/acme-dns-rust /usr/local/bin/
```

## 2. Environment Setup

### Create Service User
Create a dedicated system user without login privileges:
```bash
sudo useradd -r -s /bin/false acme-dns
```

### Config Directories
Create directories for configuration and runtime state database:
```bash
sudo mkdir -p /etc/acme-dns-rust
sudo mkdir -p /var/lib/acme-dns-rust
```

Copy the template configuration file:
```bash
sudo cp config.toml /etc/acme-dns-rust/config.toml
```

Set appropriate ownership:
```bash
sudo chown -R acme-dns:acme-dns /var/lib/acme-dns-rust
sudo chown -R root:acme-dns /etc/acme-dns-rust
sudo chmod 640 /etc/acme-dns-rust/config.toml
```

## 3. Database Setup (SQLite Example)
Edit `/etc/acme-dns-rust/config.toml` and ensure your database connection path is configured correctly:
```toml
[database]
engine = "sqlite"
connection = "/var/lib/acme-dns-rust/acme-dns.db"
```

## 4. Install Systemd Service
Copy the systemd service unit file:
```bash
sudo cp acme-dns-rust.service /etc/systemd/system/
```

### Set Admin Password
Run the CLI tool once as the service user to interactively configure your administrative password:
```bash
sudo -u acme-dns acme-dns-rust --config /etc/acme-dns-rust/config.toml users list
```
*(You will be prompted to set and confirm your new admin password).*

### Enable and Start Service
Reload systemd, enable autostart on boot, and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable acme-dns-rust
sudo systemctl start acme-dns-rust
```
*Note: The systemd unit uses `AmbientCapabilities=CAP_NET_BIND_SERVICE` allowing the service user to bind to privileged ports (like DNS port 53 and HTTP/HTTPS ports 80/443) without running as root.*

## 5. Automated HTTPS / Let's Encrypt Certificate Generation Note
When configured with `tls = "letsencrypt"` or `"letsencryptstaging"`, the server uses a **lazy, on-demand** SSL generation flow:

1. **Initial state (Idle)**: When the service starts, it creates the ACME account keys but **does not** generate the domain SSL certificate. The `api-certs/` directory will remain empty of `.pem` files.
2. **Triggering Generation**: The certificate issuance is triggered **only upon receiving the first HTTPS request** (TLS ClientHello) on the API port (443).
3. **Issuance Delay**: This initial request will pause/negotiate dynamically with Let's Encrypt for **10-30 seconds** while the DNS challenge is solved. Subseqent requests are processed instantly (sub-millisecond) from memory and disk cache.

To manually trigger and force the initial SSL certificate generation, run the following command from any terminal:
```bash
curl -k -I https://<your-acme-dns-domain>/health
```
*(The `-k` flag is required during the first call because the SSL certificate is not yet generated and signed when the handshake starts).*

---

# SECTION 2: acme-dns-client-rust (The Certbot Client Hook)

The client is a CLI tool designed to be executed by Certbot's authentication and cleanup hooks during certificate issuance.

## 1. Compilation

> **Prerequisite:** Ensure Rust and Cargo are installed. See the [Prerequisites](#prerequisites-installing-rust-and-cargo) section at the top of this document.

Build the client binary in release mode:
```bash
# Navigate to the client directory
cd acme-dns-client-rust
cargo build --release
```
The optimized executable will be generated at `./acme-dns-client-rust/target/release/acme-dns-client-rust`.

Copy the client binary to the standard executable path:
```bash
sudo cp ./target/release/acme-dns-client-rust /usr/local/bin/
```

## 2. Directory Setup
Create the state configuration directory where the client will save the registered user credentials JSON file:
```bash
sudo mkdir -p /etc/acme-dns-client
```

Ensure the user running Certbot (usually root) has read/write access to this folder.
