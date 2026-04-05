DROP TABLE IF EXISTS org_idp_configs;
ALTER TABLE oauth_providers DROP COLUMN IF EXISTS issuer_url;
ALTER TABLE oauth_providers DROP COLUMN IF EXISTS jwks_uri;
