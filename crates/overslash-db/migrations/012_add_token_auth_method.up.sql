-- How the provider expects client credentials during token exchange.
-- 'client_secret_post' = form body (default, most providers)
-- 'client_secret_basic' = HTTP Basic Auth header (X/Twitter)
ALTER TABLE oauth_providers
    ADD COLUMN token_auth_method TEXT NOT NULL DEFAULT 'client_secret_post';

UPDATE oauth_providers SET token_auth_method = 'client_secret_basic' WHERE key = 'x';
