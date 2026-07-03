-- HubSpot OAuth provider (CRM: contacts, companies, deals, notes).
--
-- HubSpot uses the standard authorization-code grant with client credentials
-- sent in the token request body (`client_secret_post`, the default) and does
-- NOT support PKCE. Access tokens are short-lived (~30m) and refresh via the
-- refresh grant, so `supports_refresh` is true. There is no bearer-token
-- userinfo endpoint (account details require the token in the path via
-- `/oauth/v1/access-tokens/{token}`), so `userinfo_endpoint` is left NULL and
-- connections are labeled without an `account_email`.
INSERT INTO oauth_providers (
    key, display_name, authorization_endpoint, token_endpoint,
    revocation_endpoint, userinfo_endpoint,
    supports_pkce, supports_refresh, extra_auth_params
) VALUES (
    'hubspot', 'HubSpot',
    'https://app.hubspot.com/oauth/authorize',
    'https://api.hubapi.com/oauth/v1/token',
    NULL,
    NULL,
    false, true, '{}'
);
