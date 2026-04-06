ALTER TABLE api_keys DROP COLUMN IF EXISTS revoked_reason;

ALTER TABLE orgs DROP COLUMN IF EXISTS subagent_archive_retention_days;
ALTER TABLE orgs DROP COLUMN IF EXISTS subagent_idle_timeout_secs;

DROP INDEX IF EXISTS idx_identities_archived;
DROP INDEX IF EXISTS idx_identities_idle_subagents;

ALTER TABLE identities DROP COLUMN IF EXISTS archived_reason;
ALTER TABLE identities DROP COLUMN IF EXISTS archived_at;
ALTER TABLE identities DROP COLUMN IF EXISTS last_active_at;
