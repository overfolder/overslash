-- HubSpot OAuth provider (CRM: contacts, companies, deals, notes) — used both
-- for HTTP action templates and for HubSpot's remote MCP server
-- (https://mcp.hubspot.com), which authenticates callers with a custom OAuth
-- ("MCP auth app") client via OAuth 2.1 + PKCE.
--
-- HubSpot uses the standard authorization-code grant with client credentials
-- in the token request body (`client_secret_post`, the default). The remote
-- MCP flow REQUIRES PKCE (S256), so `supports_pkce` is true. Access tokens are
-- short-lived (~30m) and refresh via the refresh grant (single-use rotation),
-- so `supports_refresh` is true. There is no bearer-token userinfo endpoint
-- (account details require the token in the path via
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
    true, true, '{}'
);
