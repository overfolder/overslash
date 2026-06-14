-- Token-vault model for white-label integrations. The partner runs the OAuth
-- dance itself and POSTs the resulting tokens to `/v1/connections/import`;
-- Overslash stores, refreshes, and injects them, and never issues a
-- `redirect_uri`. This makes the orchestrated white-label surface obsolete:
-- the per-org provider callback (`orgs.oauth_redirect_url`, migration 081) and
-- the per-flow custom redirect (`oauth_connection_flows.redirect_uri`,
-- migration 079) are both dropped. Every OAuth flow now completes at the
-- default `{public_url}/v1/oauth/callback`.

-- Imported connections whose refresh is the integration's responsibility (no
-- BYOC client shared with Overslash). Overslash injects the stored access
-- token until it expires, then signals `reauth_required` (flagged
-- integration-managed, with no Overslash reconnect link) instead of attempting
-- a refresh grant — it has no client to refresh against and never falls back
-- to the org/env OAuth client cascade. Orchestrated and self-refresh (pinned
-- BYOC) connections are `false`.
ALTER TABLE connections
    ADD COLUMN integration_managed boolean NOT NULL DEFAULT false;

ALTER TABLE oauth_connection_flows
    DROP COLUMN redirect_uri;

ALTER TABLE orgs
    DROP COLUMN oauth_redirect_url;
