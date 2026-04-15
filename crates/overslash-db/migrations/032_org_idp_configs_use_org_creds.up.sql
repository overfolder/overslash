-- Allow org_idp_configs to defer its client_id/secret to the org-level OAuth
-- App Credentials (org secrets OAUTH_{PROVIDER}_CLIENT_ID / _SECRET).
--
-- When both encrypted_* columns are NULL, the IdP login path resolves
-- credentials from the org's OAuth App Credentials at request time, so
-- rotating the org secret propagates to the IdP automatically (SPEC §3).
-- When both are present, the IdP has its own dedicated credentials.

ALTER TABLE org_idp_configs
    ALTER COLUMN encrypted_client_id DROP NOT NULL,
    ALTER COLUMN encrypted_client_secret DROP NOT NULL;

ALTER TABLE org_idp_configs
    ADD CONSTRAINT org_idp_configs_creds_both_or_neither
    CHECK (
        (encrypted_client_id IS NULL AND encrypted_client_secret IS NULL)
        OR (encrypted_client_id IS NOT NULL AND encrypted_client_secret IS NOT NULL)
    );
