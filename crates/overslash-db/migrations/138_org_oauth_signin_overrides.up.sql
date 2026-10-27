-- Org OAuth App Credentials (`OAUTH_{PROVIDER}_CLIENT_ID/SECRET` org secrets)
-- override the env app for service connections, but not for Overslash-managed
-- sign-in: Google/GitHub login keeps using the built-in `{PROVIDER}_AUTH_*`
-- app unless the admin opts that provider in here. A row means "the org's
-- OAuth App Credentials also serve managed sign-in for this provider".
CREATE TABLE org_oauth_signin_overrides (
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    provider_key TEXT NOT NULL REFERENCES oauth_providers(key),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, provider_key)
);
