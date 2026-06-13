-- Per-org allow-list of hosts permitted as a custom OAuth `redirect_uri` when
-- an org API key starts a white-label connect flow. Comma-separated, lowercased
-- hostnames (e.g. 'app.overfolder.com,localhost'); empty (default) disables
-- custom redirect URIs for the org. Managed from Org Settings in the dashboard.
ALTER TABLE orgs
    ADD COLUMN oauth_callback_allowed_hosts TEXT NOT NULL DEFAULT '';
