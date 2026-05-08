DROP INDEX IF EXISTS idx_secrets_owner;
ALTER TABLE secrets DROP COLUMN owner_identity_id;
