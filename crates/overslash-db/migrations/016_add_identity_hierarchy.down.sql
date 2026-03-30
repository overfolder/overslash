DROP INDEX IF EXISTS idx_identities_parent;
ALTER TABLE identities DROP COLUMN IF EXISTS depth;
ALTER TABLE identities DROP COLUMN IF EXISTS parent_id;
