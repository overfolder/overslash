-- Add OIDC discovery fields to oauth_providers
ALTER TABLE oauth_providers ADD COLUMN IF NOT EXISTS issuer_url TEXT;
ALTER TABLE oauth_providers ADD COLUMN IF NOT EXISTS jwks_uri TEXT;

-- Set known issuer URLs for existing providers
UPDATE oauth_providers SET issuer_url = 'https://accounts.google.com' WHERE key = 'google' AND issuer_url IS NULL;
UPDATE oauth_providers SET issuer_url = 'https://login.microsoftonline.com/common/v2.0' WHERE key = 'microsoft' AND issuer_url IS NULL;

-- Per-org IdP configuration for login authentication
CREATE TABLE IF NOT EXISTS org_idp_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    provider_key TEXT NOT NULL REFERENCES oauth_providers(key),
    encrypted_client_id BYTEA NOT NULL,
    encrypted_client_secret BYTEA NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    allowed_email_domains TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, provider_key)
);

CREATE INDEX IF NOT EXISTS idx_org_idp_configs_org ON org_idp_configs(org_id);
CREATE INDEX IF NOT EXISTS idx_org_idp_configs_domains ON org_idp_configs USING GIN (allowed_email_domains);
