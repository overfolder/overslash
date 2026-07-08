-- Notion public-integration OAuth provider.
--
-- Notion's OAuth 2.0 differs from the Google/GitHub norm in three ways, all
-- handled generically by the existing OAuth engine (services/oauth.rs) once
-- this row exists:
--   * token exchange authenticates with HTTP Basic (client_id:client_secret)
--     -> token_auth_method = 'client_secret_basic'
--   * the authorize URL must carry `owner=user` -> extra_auth_params, appended
--     verbatim by build_auth_url
--   * access tokens do not expire and there are no refresh tokens
--     -> supports_refresh = false
-- Notion has no OAuth scopes (capabilities are configured on the integration),
-- so scopes stay empty and default_identity_scopes keeps its '{}' default.
-- There is no userinfo endpoint: workspace/owner info rides along in the token
-- response, so userinfo_endpoint is NULL. `response_type=code` is added by
-- build_auth_url and must NOT be duplicated here.
INSERT INTO oauth_providers (
    key, display_name, authorization_endpoint, token_endpoint,
    revocation_endpoint, userinfo_endpoint,
    supports_pkce, supports_refresh, extra_auth_params, token_auth_method
) VALUES (
    'notion', 'Notion',
    'https://api.notion.com/v1/oauth/authorize',
    'https://api.notion.com/v1/oauth/token',
    NULL,
    NULL,
    false,
    false,
    '{"owner": "user"}'::jsonb,
    'client_secret_basic'
);
