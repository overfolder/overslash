-- Restore NOT NULL on org_idp_configs encrypted client_id / client_secret.
-- Any rows that deferred to org OAuth credentials would lose their mapping,
-- so drop them first — they're indistinguishable from a broken IdP without
-- the fallback path.

DELETE FROM org_idp_configs
 WHERE encrypted_client_id IS NULL
    OR encrypted_client_secret IS NULL;

ALTER TABLE org_idp_configs
    DROP CONSTRAINT IF EXISTS org_idp_configs_creds_both_or_neither;

ALTER TABLE org_idp_configs
    ALTER COLUMN encrypted_client_id SET NOT NULL,
    ALTER COLUMN encrypted_client_secret SET NOT NULL;
