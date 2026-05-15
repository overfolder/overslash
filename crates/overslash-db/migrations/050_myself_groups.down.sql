-- Reverse: drop Myself groups, the system_kind column, and the owner_identity_id column.
-- The owner-bypass logic in application code is restored separately by reverting the
-- Rust changes; this migration only undoes the schema and the data backfilled above.

-- Cascade-delete Myself groups (their group_grants and identity_groups go with them via FK).
DELETE FROM groups WHERE system_kind = 'self';

ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_owner_only_for_self;
DROP INDEX IF EXISTS idx_groups_self_per_user;

ALTER TABLE groups DROP COLUMN IF EXISTS owner_identity_id;
ALTER TABLE groups DROP COLUMN IF EXISTS system_kind;
