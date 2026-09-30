DROP TABLE IF EXISTS google_directory_connect_flows;

-- Per-org keys cannot be restored; the configs go, which cascades to their
-- Google directory groups.
DELETE FROM org_google_directory_configs;

DROP INDEX IF EXISTS org_google_directory_configs_domain_key;
ALTER TABLE org_google_directory_configs
    DROP COLUMN domain,
    DROP COLUMN connected_by_identity_id,
    DROP COLUMN connected_at,
    ADD COLUMN encrypted_service_account_key BYTEA NOT NULL,
    ADD COLUMN service_account_email TEXT NOT NULL,
    ADD COLUMN service_account_key_id TEXT NOT NULL,
    ADD COLUMN domains TEXT[] NOT NULL CHECK (cardinality(domains) > 0);
