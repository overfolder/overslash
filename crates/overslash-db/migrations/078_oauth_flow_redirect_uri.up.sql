-- Optional provider `redirect_uri` baked into the authorize URL and reused
-- verbatim at token exchange. Lets a white-label partner complete OAuth
-- against a partner-hosted callback (e.g.
-- https://app.overfolder.com/auth/google/integrations/callback) while
-- Overslash still performs the exchange. Persisting it on the flow row is what
-- guarantees the authorize-time and exchange-time values byte-match (an OAuth
-- hard requirement). NULL falls back to the historical
-- `{public_url}/v1/oauth/callback` default — fully backward-compatible.

ALTER TABLE oauth_connection_flows
    ADD COLUMN redirect_uri TEXT;
