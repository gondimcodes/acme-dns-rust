# Changelog — acme-dns-rust

## [1.2.3] / acme-dns-client-rust [1.0.3] — 2026-08-01

This release is a comprehensive code quality, security hardening, and test coverage improvement based on a full technical audit (SSDLC/OWASP/CWE review) of both projects. No breaking changes.

### 🔒 Security
- **CORS now respects `corsorigins` config** (`api.rs`): Previously the CORS layer always used `allow_origin(Any)` (wildcard), ignoring the operator's `corsorigins` setting. The CORS policy is now built from `config.toml` — only allows `*` when explicitly declared, otherwise restricts to the listed origins. (CWE-346)
- **Storage file permissions `0o600`** (`acme-dns-client-rust`): The credentials storage JSON (`/etc/acmedns/clientstorage.json`) is now created with mode `0o600`, preventing other system users from reading stored API usernames and passwords. (CWE-732)

### ⚡ Performance & Architecture
- **Rate limiter cleanup moved to background task** (`api.rs`): The `O(n)` `retain()` call that ran on every HTTP request to purge stale IP entries from the `DashMap` has been moved to a dedicated `tokio::spawn` background task that runs every 60 seconds. This eliminates CPU spikes during DDoS scenarios with a large number of unique IPs.
- **`REGISTER_LIMITER` moved from `static OnceLock` to `AppState`** (`api.rs`): The per-IP registration rate limiter was stored as a process-global `static OnceLock<DashMap>`, which is not testable in isolation and architecturally inconsistent with the rest of the state model. It is now a proper `Arc<DashMap>` field in `AppState`.
- **Background task consolidates both rate limiter cleanups**: A single periodic task in `create_router()` handles cleanup for both the general request rate limiter and the registration rate limiter.

### 🏗️ Code Quality
- **Eliminated 6-fold code duplication in `db.rs`** (`QUAL-WARN-1`): Introduced a `map_record_row!` macro that maps a database `Row` to a `Record`. This removes 6 identical blocks spread across `get_user_by_username`, `get_user_by_subdomain`, and `list_users` (each with SQLite and Postgres arms).
- **SQL migration errors are now logged** (`db.rs`): `execute_sql` no longer silently discards all errors with `let _ =`. Errors that are not idempotent (i.e., not "already exists" / "duplicate column") are now logged at `error!()` level, making unexpected migration failures visible in production logs.
- **`warn!()` for SOA serial overflow** (`dns.rs`): If the UTC timestamp-based SOA serial ever overflows `u32::MAX` (expected to occur after ~2042), the fallback to `1` now logs a `warn!()` message instead of silently resetting the serial (which would break DNS propagation).
- **`expect()` replaces `unwrap()` in client** (`acme-dns-client-rust`): The `build_resolver()` function no longer panics with an opaque message — it now produces a clear diagnostic via `expect("Failed to build DNS resolver: invalid configuration")`.
- **Duplicate `use` import removed** (`acme-dns-client-rust`): `use tokio::io::AsyncBufReadExt` was imported twice inside the same `match` arm. Moved to the top-level import list.
- **Redundant field name fixed** (`acme-dns-client-rust`): `server_url: server_url` corrected to `server_url` (clippy `redundant_field_names`).

### 🧪 Tests
- **9 new integration tests for `db.rs`** using SQLite `:memory:` — covering `register`, `allow_from`, `update_txt`, max 2 TXT records enforcement, `delete_user`, non-existent delete, `list_users`, `get_user_by_subdomain`, and admin password operations.
- Total test count: **20 tests** (up from 10).

---



This release fixes a critical bug in the orphan account cleanup routine and improves the test suite stability.

### 🔒 Bug Fixes
- **Accidental User Deletion**: Re-architected the orphan cleanup logic. We now use a persistent `HasUpdated` flag on the `records` table instead of querying the transient `txt` table (which is subject to rotation and clearing). This prevents users who have performed updates in the past from being accidentally deleted when their active TXT records expire.
- **Database Migration**: Added migration `20260715000000_add_has_updated_to_records` to automatically add the `HasUpdated` column to the `records` table and safely backfill existing users.
- **Integration Test Path**: Fixed `cleanup_test.rs` to write its database inside the `target` directory and pre-create the SQLite file to avoid path resolution and connection failures.

---

## [1.2.0] — 2026-07-11

This release adds security defenses against registration flooding and CLI auditing enhancements.

### 🔒 Security Fixes
- **Orphan Accounts Cleaner (Garbage Collection)**: Added a background cleaner thread that periodically purges accounts registered via `/register` that have not performed a TXT challenge update within a configured timeout (default: 30 minutes). Enabled by default (`cleanup_orphans = true`, `orphan_timeout_mins = 30`).
- **SQLite Schema Migration Fix**: Re-architected migrations (`20260711000000_add_created_at_to_records.sql`) to avoid adding dynamic non-constant defaults (`CURRENT_TIMESTAMP`) directly inside SQLite `ALTER TABLE ADD COLUMN` queries, preventing service crashes on existing legacy databases.

### 🏗️ Architecture & Code Quality
- **CLI CreatedAt Auditing**: Enhanced the CLI tool command `users list` to display user account creation timestamps, allowing easy detection of registration floods. Added `CAST(CreatedAt AS TEXT)` on SQL queries to prevent genenic driver parsing type mismatch errors on `sqlx::AnyPool`.
- **Integration Test Suite**: Created `cleanup_test.rs` to automatically verify the cleanup algorithm using `/tmp` temporary SQLite connections.

---

## [1.1.0] — 2026-07-10

This release introduces a complete technical audit and revision focusing on security, performance, architecture, and overall service stability.

### 🔒 Security Fixes
- **SEG-01 / SEG-02 — Rate Limiter & IP Spoofing**: The API rate limiter now correctly extracts the real client IP via proxy headers (like `X-Forwarded-For`), applying strict validation against the configured list of CIDRs for trusted proxies (`trusted_proxies` in `config.toml`) to prevent bypasses.
- **SEG-03 — Whitelist Fail-Closed**: Fixed a critical vulnerability where the IP access whitelist was bypassed if the client IP could not be determined. The logic is now *fail-closed* (access denied by default).
- **SEG-04 — Challenge TXT Validation**: Implemented strict validation of the `txt` value in the `/update` endpoint. Values that are not valid ACME DNS-01 tokens (Base64URL of exactly 43 characters) are immediately rejected with a `400 Bad Request`.
- **SEG-05 — API Payload Limitation**: Reduced the request body limit for API endpoints from 16 KB to 1 KB, mitigating potential DoS attacks from resource or bandwidth exhaustion.
- **SEG-06 — Elimination of Panics (`unwrap`)**: All silent panics (`unwrap` and `expect`) during service initialization and DNS/HTTP request handling have been removed or replaced with robust structured error propagation.
- **SEG-07 — Timing Equalization**: Introduced artificial delay during credentials verification (`dummy_verify`) for non-existent users, preventing timing attacks that allowed username enumeration.
- **SEG-08 — Admin Password Strength Policy**: Increased the minimum admin password length from 6 to 12 characters.
- **SEG-09 — Rate Limiter Memory Leak**: Added periodic cleanup (`limits.retain`) of stale IP entries in the rate limiter, preventing memory leaks under high volumes of scanner or crawler traffic.
- **SEG-11 / SEG-12 — CORS & HSTS Integration**: Fixed inactive code blocks. CORS configuration directives and HTTP Strict Transport Security (HSTS) headers are now actively applied and sent.
- **QUAL-08 — Deserialization Error Handling**: Failures to decode access control parameters (`AllowFrom` corruption in the database) now log `WARN` alerts instead of silently returning empty lists, avoiding hidden security bypasses.

### ⚡ Performance
- **PERF-01 — Lock-Free Rate Limiter**: Replaced the global `Mutex<HashMap>` with a concurrent `DashMap` for the rate limiter, removing throughput bottlenecks and global locking overhead.
- **PERF-02 — Arc Config Sharing**: The service configuration (`Config`) is now shared via `Arc<Config>` across API worker threads, avoiding deep clone operations on every incoming HTTP connection.
- **PERF-03 — DNS Server TXT Record Cache**: Added a concurrent in-memory cache with a 2-second TTL (powered by the `moka` crate) for TXT record resolution in the DNS handler, significantly reducing query overhead to the SQLite/Postgres database.
- **PERF-04 — SOA Serial Parse Optimization**: The SOA serial number (`serial_u32`) is now parsed and cached once during zone initialization, eliminating redundant string parsing inside loops.

### 🏗️ Architecture & Code Quality
- **QUAL-01 — Unified Database Layer (AnyPool)**: Re-engineered the database interface (`db.rs`) using `sqlx::AnyPool`. Massive code duplication between SQLite and Postgres database statement branches has been entirely eliminated.
- **QUAL-02 / QUAL-04 — Clap-Based CLI**: Replaced manual command-line argument parsing in `main.rs` with a declarative structure using the `clap` crate, and decoupled CLI logic into a new `cli.rs` module.
- **ARQ-01 — Automated Test Coverage**: Introduced robust unit testing in `auth.rs` (covering password checks, length limits, and token validations) and integration tests in `tests/config_test.rs`.
- **ARQ-02 — Graceful Shutdown**: Added proper signal handling for `SIGINT` (Ctrl-C) and `SIGTERM` (systemd stop standard), ensuring database pools are drained and connections are closed cleanly.
- **ARQ-03 — Versioned SQL Migrations**: Integrated automated migrations using sqlx (`migrations/`), allowing clean database schema setups and backward compatibility with existing legacy tables.
- **ARQ-05 — Prometheus Metrics**: Integrated native observability metrics using the `metrics` crate, exposing a `/metrics` API endpoint providing counters for endpoint requests and active connections.
