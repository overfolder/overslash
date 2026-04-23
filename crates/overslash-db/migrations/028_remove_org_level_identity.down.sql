-- Reverse 028: re-allow NULL identity_id on api_keys and byoc_credentials,
-- and drop the is_org_admin column. This is forward-only in spirit; the
-- down-migration exists for local dev only and does not restore deleted rows.

ALTER TABLE byoc_credentials
    ALTER COLUMN identity_id DROP NOT NULL;

CREATE UNIQUE INDEX byoc_credentials_org_provider_null_identity
    ON byoc_credentials (org_id, provider_key) WHERE identity_id IS NULL;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_identity_id_fkey;
ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_identity_id_fkey
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE SET NULL;
ALTER TABLE api_keys
    ALTER COLUMN identity_id DROP NOT NULL;

ALTER TABLE identities DROP CONSTRAINT identities_is_org_admin_only_user;
ALTER TABLE identities DROP COLUMN is_org_admin;
