-- Add HasUpdated column to records table
ALTER TABLE records ADD COLUMN HasUpdated INTEGER NOT NULL DEFAULT 0;

-- Backfill all existing records to HasUpdated = 1 to prevent their accidental deletion
UPDATE records SET HasUpdated = 1;
