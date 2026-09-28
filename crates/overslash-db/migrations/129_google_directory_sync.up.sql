-- Google Workspace Directory as a second directory-group source.
--
-- Google never releases group membership in its ID token or `/userinfo`, so
-- the OIDC-claim source of migration 128 gives a Workspace org nothing. This
-- source pulls membership from the Admin SDK Directory API instead, with a
-- service account the org delegates domain-wide authority to. It writes the
-- same `directory_groups` / `identity_directory_groups` tables under
-- `source = 'google_directory'` and `idp_config_id = NULL` — the shape 127
-- reserved for it. Nothing about how a directory group becomes access changes:
-- only an admin-drawn `group_directory_sources` edge confers anything.
--
-- See `docs/design/directory-group-sync.md` → "Google Directory source".

ALTER TABLE directory_groups DROP CONSTRAINT directory_groups_source_check;
ALTER TABLE directory_groups
    ADD CONSTRAINT directory_groups_source_check
    CHECK (source IN ('oidc_claim', 'google_directory'));

-- One Google directory per org. The credential is the org's own, which is
-- what lets this source speak about the org at all (D12); `domains` bounds
-- which of the org's humans it may speak about.
CREATE TABLE org_google_directory_configs (
    org_id UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    -- The whole service-account JSON key, AES-256-GCM encrypted. Never
    -- returned by the API; the two columns below are what the dashboard shows.
    encrypted_service_account_key BYTEA NOT NULL,
    service_account_email TEXT NOT NULL,
    service_account_key_id TEXT NOT NULL,
    -- The Workspace admin the service account impersonates. Directory reads
    -- under domain-wide delegation must name a subject with admin rights.
    admin_subject TEXT NOT NULL,
    customer_id TEXT NOT NULL DEFAULT 'my_customer',
    -- Lower-cased email domains whose users this source reconciles. An
    -- identity outside them is never touched, whatever Google reports.
    domains TEXT[] NOT NULL CHECK (cardinality(domains) > 0),
    enabled BOOLEAN NOT NULL DEFAULT true,
    sync_interval_hours INTEGER NOT NULL DEFAULT 8
        CHECK (sync_interval_hours BETWEEN 1 AND 168),

    -- Scheduling. A row is due when it is enabled, unleased (or the lease
    -- expired), and either a manual run is queued or `next_sync_at` passed.
    next_sync_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The manual queue. One nullable column rather than a jobs table makes
    -- "at most one queued run" structural: a second click finds it already
    -- set and changes nothing. The claim clears it, so a click that lands
    -- during a run queues exactly one follow-up.
    sync_requested_at TIMESTAMPTZ,
    lease_owner TEXT,
    lease_expires_at TIMESTAMPTZ,

    last_sync_started_at TIMESTAMPTZ,
    last_sync_finished_at TIMESTAMPTZ,
    last_sync_status TEXT CHECK (last_sync_status IN ('ok', 'error')),
    last_sync_error TEXT,
    last_sync_stats JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Google rows hang off the config that reported them. Set by
-- `directory_group::upsert` for `source = 'google_directory'` only; the CHECK
-- holds the two in lockstep. The FK is what makes Disconnect atomic against an
-- in-flight sweep: deleting the config cascades to its groups (and from them
-- to memberships and mappings), and a sweep's upsert landing after the DELETE
-- fails on the missing parent instead of resurrecting the groups.
ALTER TABLE directory_groups
    ADD COLUMN google_directory_org_id UUID
        REFERENCES org_google_directory_configs(org_id) ON DELETE CASCADE,
    ADD CONSTRAINT directory_groups_google_directory_org_check
        CHECK ((source = 'google_directory') = (google_directory_org_id IS NOT NULL));

CREATE INDEX idx_directory_groups_google_directory_org
    ON directory_groups(google_directory_org_id)
    WHERE google_directory_org_id IS NOT NULL;

CREATE INDEX idx_org_google_directory_configs_due
    ON org_google_directory_configs(next_sync_at)
    WHERE enabled;
