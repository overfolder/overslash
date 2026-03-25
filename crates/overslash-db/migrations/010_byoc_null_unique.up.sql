-- Fix: UNIQUE(org_id, identity_id, provider_key) doesn't prevent duplicates
-- when identity_id IS NULL (PostgreSQL NULL != NULL). Add a partial index.
CREATE UNIQUE INDEX byoc_credentials_org_provider_null_identity
    ON byoc_credentials (org_id, provider_key) WHERE identity_id IS NULL;
