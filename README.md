# acme-dns-rust & acme-dns-client-rust

A robust, modular infrastructure written in Rust to automate Let's Encrypt DNS-01 verification challenges.

---

## Workspace Directory Structure

```text
acme-dns-rust/
├── Cargo.toml                  # Rust package manager configuration
├── config.toml                 # Default configuration file template for the server
├── acme-dns-rust.service       # Systemd service unit template file
├── migrate.sh                  # Database migration script from Go SQLite to Rust SQLite
├── AUTHOR.md                   # Author details
├── LICENSE                     # GNU General Public License v3
├── README.md                   # Project administration & structural documentation
├── INSTALL.md                  # Installation & compilation guide (Server and Client)
├── acme-dns-client-rust/       # Sub-crate containing the Let's Encrypt Certbot client hook
│   ├── Cargo.toml
│   └── src/
│       └── main.rs             # Client source code
└── src/                        # Server source code
    ├── main.rs                 # Server CLI entrypoint & spawner
    ├── config.rs               # TOML Configuration file parser
    ├── auth.rs                 # Hashing (bcrypt) & authentication logic
    ├── db.rs                   # Database abstraction layer (SQLite & Postgres)
    ├── dns.rs                  # Hickory-based DNS Server implementation
    └── api.rs                  # Axum-based HTTP/HTTPS REST API
```

---

## Source Code Files Documentation

### 1. acme-dns-rust (The Server)

* **`src/main.rs`**: Entrypoint of the server binary. It handles CLI parsing (admin commands), initializes logging, configures the SQLite/PostgreSQL connection pool, and spawns the DNS UDP/TCP service and HTTP/HTTPS Axum web endpoints.
* **`src/config.rs`**: Parses TOML configurations into runtime memory structures.
* **`src/auth.rs`**: Security and hashing helper (generates random credentials and runs bcrypt checks).
* **`src/db.rs`**: Handles SQLite/PostgreSQL operations (registering users, managing dynamic TXT tokens, user deletion).
* **`src/dns.rs`**: Extends Hickory DNS to serve dynamic challenge TXT records directly from the database, handling fallback mapping to static zones.
* **`src/api.rs`**: Exposes Axum endpoints (`/register`, `/update`, `/health`), validates source IPs against allowed CIDRs, and drives Let's Encrypt TLS-ALPN-01 dynamic certificates generation.

---

# SECTION 1: acme-dns-rust (The Server)

The `acme-dns-rust` server serves dynamic DNS challenge TXT records for DNS-01 verification and provides an API for registrations.

## 1. CLI Administration Utilities
All administrative commands require authentication via the admin password configured during the first run.

### List Registered Users
```bash
acme-dns-rust --config /etc/acme-dns-rust/config.toml users list
```

### Delete a User
Safely deletes an API user and cleans up all dynamic validation TXT records linked to their subdomain:
```bash
acme-dns-rust --config /etc/acme-dns-rust/config.toml users delete <username_uuid>
```

### View Active TXT Records
View current dynamic challenge verification TXT tokens for any user or subdomain UUID:
```bash
acme-dns-rust --config /etc/acme-dns-rust/config.toml users txt <username_or_subdomain_uuid>
```

### Change Admin Password
```bash
acme-dns-rust --config /etc/acme-dns-rust/config.toml users passwd
```

## 2. Service Management

### Check Logs
```bash
journalctl -u acme-dns-rust.service -f
```

### Service Controls
```bash
# Restart the service
sudo systemctl restart acme-dns-rust

# Check status
sudo systemctl status acme-dns-rust
```

## 3. Database Migration
A helper script `migrate.sh` is provided in the repository to migrate existing SQLite databases from the original Go project to `acme-dns-rust`:
```bash
./migrate.sh /path/to/original/acme-dns.db /var/lib/acme-dns-rust/acme-dns.db
```

---

# SECTION 2: acme-dns-client-rust (The Certbot Client Hook)

The client CLI tool handles dynamic registration and token updates automatically when triggered by Certbot.

## 1. Source Code Files Documentation

* **`acme-dns-client-rust/src/main.rs`**: Entrypoint of the client binary. It implements commands to register accounts with an `acme-dns` server, manage credentials locally in JSON format (usually in `/etc/acme-dns-client/clientstorage.json`), query CNAME/CAA configurations dynamically using `hickory-resolver`, and handles the automated Certbot hooks for domain validation.

---

## 2. CLI Operations & Certbot Integration

### Manual Domain Registration (Initial Setup)
Before generating certificates, you can register a new domain in your server instance to set up CNAME records:
```bash
acme-dns-client-rust -s https://auth.domain.com register -d <FQDN>
```
*(This command will output the required DNS CNAME records to point your domain to the acme-dns server).*

### Registering and Issuing Certificates via Certbot
To issue certificates automatically, add the client hooks to your Certbot command:
```bash
certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook '/usr/local/bin/acme-dns-client-rust' \
  -d "*.example.com" -d "example.com"
```

### Authentication Flow (Automatic)
During the authentication hook step, the client will:

1. Check if the subdomain registration credentials JSON exists in `/etc/acme-dns-client/`.
2. If not found, it automatically requests new API credentials from the registration endpoint (`/register`) of the configured `acme-dns-rust` server.
3. Prints the required DNS CNAME record for your domain (e.g. `_acme-challenge.example.com CNAME <subdomain_uuid>.auth.example.com`).
4. Updates the TXT value in the server API (`/update`) and sleeps for 10 seconds to allow DNS propagation.

### Cleanup Flow (Automatic)
During the cleanup hook step, the client updates the TXT value in the server API to empty strings, cleaning up the validation state.
