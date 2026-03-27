INSERT INTO oauth_providers (
    key, display_name, authorization_endpoint, token_endpoint,
    revocation_endpoint, userinfo_endpoint,
    supports_pkce, supports_refresh, extra_auth_params
) VALUES (
    'x', 'X (Twitter)',
    'https://twitter.com/i/oauth2/authorize',
    'https://api.twitter.com/2/oauth2/token',
    'https://api.twitter.com/2/oauth2/revoke',
    'https://api.twitter.com/2/users/me',
    true, true, '{}'
);
