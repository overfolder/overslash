-- White-label / BYOC orgs whose end users have no Overslash dashboard session.
-- For a headless org, auth-recovery on an action call (`reauth_required`,
-- `needs_authentication`, `missing_scopes`) returns a typed, URL-less envelope
-- (no gated `/connect-authorize` link, no `oauth_connection_flows` row) instead
-- of minting a user-facing URL the org's users could never open. The
-- integration re-runs its own OAuth dance and re-imports via
-- `POST /v1/connections/import`. Default `false`: normal orgs keep the gated
-- dashboard flow. See `docs/design/white-label-token-vault.md`.
ALTER TABLE orgs
    ADD COLUMN headless boolean NOT NULL DEFAULT false;
