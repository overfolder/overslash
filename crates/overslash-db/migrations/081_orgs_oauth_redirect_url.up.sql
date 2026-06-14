-- White-label OAuth: a single admin-set provider `redirect_uri` per org (the
-- partner-hosted callback). A connect/reauth flow opts into it per request via
-- `use_org_redirect`; empty (default) means the org has no white-label callback.
-- Managed from Org Settings in the dashboard. Replaces the previous per-request
-- `redirect_uri` override + `oauth_callback_allowed_hosts` allow-list.
ALTER TABLE orgs
    ADD COLUMN oauth_redirect_url TEXT NOT NULL DEFAULT '';
ALTER TABLE orgs
    DROP COLUMN oauth_callback_allowed_hosts;
