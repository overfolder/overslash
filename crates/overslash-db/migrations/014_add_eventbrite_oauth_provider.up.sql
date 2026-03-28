INSERT INTO oauth_providers (
    key, display_name, authorization_endpoint, token_endpoint,
    revocation_endpoint, userinfo_endpoint,
    supports_pkce, supports_refresh, extra_auth_params
) VALUES (
    'eventbrite', 'Eventbrite',
    'https://www.eventbrite.com/oauth/authorize',
    'https://www.eventbrite.com/oauth/token',
    NULL,
    'https://www.eventbriteapi.com/v3/users/me/',
    false, false, '{}'
);
