-- LinkedIn OAuth provider (Sign In with LinkedIn using OpenID Connect +
-- Share on LinkedIn). LinkedIn does not offer PKCE for the member auth code
-- flow and expects client credentials in the token request body
-- (client_secret_post). Refresh tokens are partner-gated, but the column
-- reflects provider capability, not per-connection grant.
--
-- default_identity_scopes: the userinfo endpoint is OIDC — `openid` is required
-- and `profile`/`email` populate the fields we label the connection with.
INSERT INTO oauth_providers (
    key, display_name, authorization_endpoint, token_endpoint,
    revocation_endpoint, userinfo_endpoint,
    supports_pkce, supports_refresh, token_auth_method,
    issuer_url, jwks_uri, default_identity_scopes, extra_auth_params
) VALUES (
    'linkedin', 'LinkedIn',
    'https://www.linkedin.com/oauth/v2/authorization',
    'https://www.linkedin.com/oauth/v2/accessToken',
    'https://www.linkedin.com/oauth/v2/revoke',
    'https://api.linkedin.com/v2/userinfo',
    false, true, 'client_secret_post',
    'https://www.linkedin.com/oauth',
    'https://www.linkedin.com/oauth/openid/jwks',
    '{openid,profile,email}', '{}'
);
