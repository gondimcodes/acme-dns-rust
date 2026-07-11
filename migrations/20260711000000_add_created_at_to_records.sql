-- Add CreatedAt column to records table for existing databases
-- SQLite does not allow adding a column with non-constant default values (like CURRENT_TIMESTAMP)
-- to an existing table. We add it as nullable first, backfill it, and manage insertions in Rust.
ALTER TABLE records ADD COLUMN CreatedAt DATETIME;

UPDATE records SET CreatedAt = CURRENT_TIMESTAMP WHERE CreatedAt IS NULL;
