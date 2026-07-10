-- ARQ-03: Initial schema migration matching the exact legacy schema definition
-- to ensure compatibility with existing databases.

CREATE TABLE IF NOT EXISTS records (
    Username   TEXT NOT NULL PRIMARY KEY,
    Password   TEXT NOT NULL,
    Subdomain  TEXT NOT NULL UNIQUE,
    AllowFrom  TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS txt (
    Subdomain  TEXT NOT NULL,
    Value      TEXT NOT NULL DEFAULT '',
    LastUpdate DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin (
    Password TEXT NOT NULL DEFAULT ''
);
