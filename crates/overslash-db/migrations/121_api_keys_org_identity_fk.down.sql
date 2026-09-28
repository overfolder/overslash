CREATE INDEX idx_api_keys_org ON api_keys (org_id);
DROP INDEX idx_api_keys_org_identity;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_org_id_identity_id_fkey;

ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_identity_id_fkey
    FOREIGN KEY (identity_id) REFERENCES identities (id) ON DELETE CASCADE;

ALTER TABLE identities
    DROP CONSTRAINT identities_org_id_id_key;
