-- Figma OAuth provider, and the one column its flow needs that no provider
-- before it did.
--
-- Every provider seeded so far refreshes at the same URL it mints tokens from,
-- so `refresh_token` in the OAuth engine posted straight to `token_endpoint`.
-- Figma does not: it documents `POST /v1/oauth/refresh`, separate from
-- `POST /v1/oauth/token`. NULL keeps the old behaviour — "refresh where you
-- minted" — so no existing provider moves.
--
-- Getting this wrong would not fail in review. Figma access tokens last 90
-- days, so a refresh pointed at the wrong URL works perfectly until a quarter
-- after the first connection, then every Figma service stops at once.
ALTER TABLE oauth_providers ADD COLUMN refresh_endpoint TEXT;

COMMENT ON COLUMN oauth_providers.refresh_endpoint IS
    'Where the refresh grant is posted, when the provider does not accept it at '
    'token_endpoint. NULL means refresh at token_endpoint.';

-- Figma authenticates the token request with HTTP Basic
-- (`client_secret_basic`), supports PKCE with S256 only, and issues refresh
-- tokens. It is not an OIDC provider — no issuer, no JWKS — but `/v1/me`
-- answers a bearer token with `{id, email, handle, img_url}`, which is enough
-- for the callback to name and picture the connection, so it is wired as the
-- userinfo endpoint. Figma documents no revocation endpoint and no
-- account-hint parameter on the authorize URL, so both stay NULL rather than
-- pushing an unknown parameter at a strict authorization server.
--
-- `current_user:read` is the minimum that makes `/v1/me` answer, so it is the
-- default identity scope: without it the callback cannot label the connection.
--
-- `response_type=code` is added by `build_auth_url` and must NOT be duplicated
-- in extra_auth_params.
INSERT INTO oauth_providers (
    key, display_name, authorization_endpoint, token_endpoint, refresh_endpoint,
    revocation_endpoint, userinfo_endpoint,
    supports_pkce, supports_refresh, token_auth_method,
    issuer_url, jwks_uri, default_identity_scopes, extra_auth_params,
    login_hint_param
) VALUES (
    'figma', 'Figma',
    'https://www.figma.com/oauth',
    'https://api.figma.com/v1/oauth/token',
    'https://api.figma.com/v1/oauth/refresh',
    NULL,
    'https://api.figma.com/v1/me',
    true, true, 'client_secret_basic',
    NULL, NULL, '{current_user:read}', '{}',
    NULL
);
