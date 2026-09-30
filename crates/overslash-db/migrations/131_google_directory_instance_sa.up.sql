-- Google Workspace Directory sync: one service account per instance, not one
-- key per org.
--
-- Migration 129 had each org upload its own service-account JSON key. The
-- instance now owns a single service account (configured by the operator via
-- `OVERSLASH_GOOGLE_DIRECTORY_SA_KEY` / `_FILE`), and an org's Workspace admin
-- only grants that account's client ID domain-wide delegation in
-- admin.google.com. See the D113 entry in DECISIONS.md.
--
-- One shared account means every connected Workspace has delegated to the
-- same client ID, so Google no longer separates tenants — Overslash must. An
-- org therefore proves which Workspace it is by signing in with Google as an
-- admin of it: the `hd` Google returns becomes `domain`, the signed-in email
-- becomes `admin_subject`, and `domain` is unique per instance so a second
-- org cannot attach a Workspace someone else already connected.

-- Per-org keys go. Existing rows cannot be carried over: they name an admin
-- who was typed, never proven, and their key is the org's, not the instance's.
-- Deleting the configs cascades (129's FK) to their Google directory groups,
-- memberships and mappings — the same effect as a Disconnect.
DELETE FROM org_google_directory_configs;

ALTER TABLE org_google_directory_configs
    DROP COLUMN encrypted_service_account_key,
    DROP COLUMN service_account_email,
    DROP COLUMN service_account_key_id,
    DROP COLUMN domains,
    -- The Workspace's primary domain, as Google's `hd` claim reported it when
    -- an admin of it signed in. Bounds which humans the sync may speak about.
    ADD COLUMN domain TEXT NOT NULL,
    -- The Google account that proved the domain. Audit only.
    ADD COLUMN connected_by_identity_id UUID REFERENCES identities(id) ON DELETE SET NULL,
    ADD COLUMN connected_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- One org per Workspace per instance. Without this, a second org whose admin
-- happened to hold a Google account in the same Workspace could attach it too.
CREATE UNIQUE INDEX org_google_directory_configs_domain_key
    ON org_google_directory_configs (lower(domain));

-- An in-flight "Sign in with Google" connect. Single use: the callback
-- deletes the row it consumes. Bound to the identity that started it, so the
-- callback refuses a browser whose session is anyone else's — otherwise an
-- org admin could mail the auth link to a victim Workspace admin and attach
-- the victim's directory to their own org.
CREATE TABLE google_directory_connect_flows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    pkce_verifier TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_google_directory_connect_flows_expires
    ON google_directory_connect_flows (expires_at);
