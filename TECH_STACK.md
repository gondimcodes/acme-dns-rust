# Technology Stack & Architecture — acme-dns-rust

This document provides a comprehensive overview of the technology stack, external crates, database integration, DNS server engine, security features, and CI/CD pipelines powering **acme-dns-rust** (v1.2.3).

---

## 1. Core Language & Runtime

* **Language**: **Rust (2024 Edition)**
  * **Rationale**: Memory-safe execution without garbage collection latency, high-concurrency async I/O handling, and reliability for mission-critical DNS validation.
* **Async Runtime**: [`tokio 1.x`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L15) (`features = ["full"]`)
  * **Usage**: Asynchronous execution for both the HTTP REST API server and the DNS server, task spawning, timers, and streaming socket handlers.

---

## 2. HTTP Web Framework & REST API

* **Web Framework**: [`axum 0.7`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L16) (`features = ["macros"]`)
  * **Usage**: Provides the REST API endpoints (`/register`, `/update`, `/health`, `/metrics`) for ACME clients to register records and update `_acme-challenge` TXT values.
* **HTTP Utilities & CORS**: [`tower-http 0.5`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L31) and [`tower 0.5`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L38)
  * **Usage**: Request middleware, CORS header control, and service layer composition.

---

## 3. DNS Server Engine

* **DNS Protocol Implementation**: [`hickory-server 0.26`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L26) (formerly Trust-DNS)
  * **Usage**: High-performance authoritative DNS server listening on UDP/TCP port 53 to answer DNS `TXT` inquiries for ACME verification domains.

---

## 4. Database Layer & Caching

* **Database Driver**: [`sqlx 0.8`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L21-L23)
  * **Supported Databases**: Dual support for **SQLite** (bundled) and **PostgreSQL**.
  * **Async Connections**: Fully asynchronous database queries for user registrations and TXT record lookups.
* **High-Performance In-Memory Cache**: [`moka 0.12`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L34) and [`dashmap 6.x`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L33)
  * **Usage**: Ultra-fast DNS TXT record lookups cached in RAM to prevent database bottlenecks during massive ACME verification storms.

---

## 5. TLS, Cryptography & Security

* **TLS Protocol Stack**: [`rustls 0.23`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L39), [`tokio-rustls 0.26`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L40), and [`axum-server 0.8`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L43) (`features = ["tls-rustls"]`)
  * **Crypto Provider**: `ring` cryptographic provider.
  * **Auto-TLS via ACME**: [`rustls-acme 0.11`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L45) and [`rcgen 0.13`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L44) for automatic HTTPS certificate issuance and self-signed certificate generation.
* **Password Hashing**: [`bcrypt 0.15`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L24)
  * **Usage**: Hashing credentials stored for API user authentication.

---

## 6. Observability & Telemetry

* **Logging & Tracing**: [`tracing 0.1`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L27) and [`tracing-subscriber 0.3`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L28)
  * **Usage**: Structured, environment-filtered logging (`RUST_LOG`).
* **Prometheus Metrics**: [`metrics 0.24`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L48) and [`metrics-exporter-prometheus 0.16`](file:///home/gondim/projetos/acme-dns-rust/Cargo.toml#L49)
  * **Usage**: Real-time HTTP and DNS performance metrics exposed for Prometheus monitoring.

---

## 7. Multi-Platform CI/CD Infrastructure & Code Mirroring

* **GitHub Actions Workflows**: Automated testing, linting (`cargo check`, `cargo test`), and cross-platform static binary build workflows.
* **Codeberg Pipeline (`.woodpecker.yml`)**:
  * **Woodpecker CI**: Automated testing (`cargo test`) and release packaging (`acme-dns-rust-linux-amd64.tar.gz` and `acme-dns-client-rust-linux-amd64.tar.gz`) attached to Codeberg Releases on tag events via `woodpeckerci/plugin-release`.
