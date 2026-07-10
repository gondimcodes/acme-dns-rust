#!/usr/bin/env bash
# acme-dns migration script (from Go SQLite database to Rust SQLite database)

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <path_to_original_acme-dns.db> <path_to_new_acme-dns-rust.db>"
    exit 1
fi

SRC_DB="$1"
DST_DB="$2"

if [ ! -f "$SRC_DB" ]; then
    echo "Error: Source database file '$SRC_DB' not found."
    exit 1
fi

# Ensure destination directory exists
mkdir -p "$(dirname "$DST_DB")"

# Touch destination file if it doesn't exist
touch "$DST_DB"

echo "Migrating data from '$SRC_DB' to '$DST_DB'..."

# Export and import via sqlite3 commands
# Note: Using sqlite3 to dump data from acmedns, records, and txt tables directly.
# Since schemas are identical, we can perform INSERT OR IGNORE / INSERT OR REPLACE.

# Check if the 'admin' table exists in the source database using sqlite3
HAS_ADMIN=$(sqlite3 "$SRC_DB" "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='admin';")

ADMIN_MIGRATE_QUERY=""
if [ "$HAS_ADMIN" -eq 1 ]; then
    echo "Admin table found in source database. Migrating administrative password..."
    ADMIN_MIGRATE_QUERY="INSERT OR REPLACE INTO admin (Password) SELECT Password FROM src.admin;"
else
    echo "No admin table found in source database. Retaining existing destination admin password."
fi

sqlite3 "$DST_DB" <<EOF
-- Initialize destination tables if not created yet
CREATE TABLE IF NOT EXISTS acmedns(Name TEXT, Value TEXT);
CREATE TABLE IF NOT EXISTS records(
    Username TEXT UNIQUE NOT NULL PRIMARY KEY,
    Password TEXT UNIQUE NOT NULL,
    Subdomain TEXT UNIQUE NOT NULL,
    AllowFrom TEXT
);
CREATE TABLE IF NOT EXISTS txt(
    Subdomain TEXT NOT NULL,
    Value TEXT NOT NULL DEFAULT '',
    LastUpdate INT
);
CREATE INDEX IF NOT EXISTS idx_txt_subdomain ON txt (Subdomain);
CREATE TABLE IF NOT EXISTS admin(Password TEXT NOT NULL);

-- Attach source database
ATTACH DATABASE '$SRC_DB' AS src;

-- Migrate acmedns configuration metadata
INSERT OR REPLACE INTO acmedns (Name, Value) SELECT Name, Value FROM src.acmedns;

-- Migrate registered users credentials
INSERT OR REPLACE INTO records (Username, Password, Subdomain, AllowFrom) 
SELECT Username, CAST(Password AS TEXT), Subdomain, AllowFrom FROM src.records;

-- Migrate current dynamic challenge tokens
INSERT OR REPLACE INTO txt (Subdomain, Value, LastUpdate) 
SELECT Subdomain, Value, LastUpdate FROM src.txt;

-- Conditionally migrate admin password
$ADMIN_MIGRATE_QUERY

DETACH DATABASE src;
EOF

echo "Migration completed successfully!"
