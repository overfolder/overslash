-- Migration 064: secrets become identity-owned.
--
-- Adds `secrets.owner_identity_id` so each secret carries an owning
-- identity (NULL = legacy / org-wide / admin-only). Visibility for
-- non-admin callers is computed by walking `identities.parent_id`
-- downward from the calling identity and matching against this column.
--
-- Backfill assigns each existing secret the v1 creator that owned the
-- slot under the prior model — preserves dashboard behavior for rows
-- created before this migration. NULL `created_by` rows (where the
-- creating identity was deleted) end up with NULL `owner_identity_id`
-- and become admin-only post-migration.

ALTER TABLE secrets ADD COLUMN owner_identity_id UUID
    REFERENCES identities(id) ON DELETE SET NULL;

CREATE INDEX idx_secrets_owner ON secrets(owner_identity_id)
    WHERE owner_identity_id IS NOT NULL;

UPDATE secrets s
SET owner_identity_id = (
    SELECT sv.created_by
    FROM secret_versions sv
    WHERE sv.secret_id = s.id AND sv.version = 1
    LIMIT 1
);
