-- OAuth provider configuration (seeded with built-in providers)
CREATE TABLE oauth_providers (
    key TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    authorization_endpoint TEXT NOT NULL,
    token_endpoint TEXT NOT NULL,
    revocation_endpoint TEXT,
    userinfo_endpoint TEXT,
    client_id_pattern TEXT,
    supports_pkce BOOLEAN NOT NULL DEFAULT false,
    supports_refresh BOOLEAN NOT NULL DEFAULT true,
    extra_auth_params JSONB NOT NULL DEFAULT '{}',
    is_builtin BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- BYOC credentials: per-org or per-identity OAuth client credentials
CREATE TABLE byoc_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    identity_id UUID REFERENCES identities(id) ON DELETE CASCADE,
    provider_key TEXT NOT NULL REFERENCES oauth_providers(key),
    encrypted_client_id BYTEA NOT NULL,
    encrypted_client_secret BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, identity_id, provider_key)
);

-- OAuth connections (tokens obtained via OAuth flow)
CREATE TABLE connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    provider_key TEXT NOT NULL REFERENCES oauth_providers(key),
    encrypted_access_token BYTEA NOT NULL,
    encrypted_refresh_token BYTEA,
    token_expires_at TIMESTAMPTZ,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    account_email TEXT,
    byoc_credential_id UUID REFERENCES byoc_credentials(id) ON DELETE SET NULL,
    is_default BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_connections_identity ON connections(identity_id);
CREATE INDEX idx_connections_provider ON connections(org_id, provider_key);

-- Seed built-in OAuth providers
INSERT INTO oauth_providers (key, display_name, authorization_endpoint, token_endpoint, userinfo_endpoint, extra_auth_params) VALUES
('google', 'Google', 'https://accounts.google.com/o/oauth2/v2/auth', 'https://oauth2.googleapis.com/token', 'https://www.googleapis.com/oauth2/v3/userinfo', '{"access_type": "offline", "prompt": "consent"}'),
('github', 'GitHub', 'https://github.com/login/oauth/authorize', 'https://github.com/login/oauth/access_token', 'https://api.github.com/user', '{}'),
('slack', 'Slack', 'https://slack.com/oauth/v2/authorize', 'https://slack.com/api/oauth.v2.access', NULL, '{}'),
('spotify', 'Spotify', 'https://accounts.spotify.com/authorize', 'https://accounts.spotify.com/api/token', 'https://api.spotify.com/v1/me', '{}'),
('microsoft', 'Microsoft', 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', 'https://login.microsoftonline.com/common/oauth2/v2.0/token', 'https://graph.microsoft.com/v1.0/me', '{}');
