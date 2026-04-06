-- Sub-agent idle cleanup with two-phase archive (SPEC §4: ephemeral workers)
--
-- Replaces the previous TTL-based design. Sub-agents are garbage-collected
-- when they go idle (no API activity for a configurable window). Cleanup
-- runs in two phases:
--   1. Archive: revoke API keys, expire pending approvals, set archived_at
--   2. Purge:   hard-delete archived rows after a retention window
-- Restore is possible during the retention window and resurrects API keys
-- that were auto-revoked by the archive.

-- Identity activity + archive state
ALTER TABLE identities ADD COLUMN last_active_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE identities ADD COLUMN archived_at TIMESTAMPTZ;
ALTER TABLE identities ADD COLUMN archived_reason TEXT;

CREATE INDEX idx_identities_idle_subagents
    ON identities(last_active_at)
    WHERE kind = 'sub_agent' AND archived_at IS NULL;

CREATE INDEX idx_identities_archived
    ON identities(archived_at)
    WHERE archived_at IS NOT NULL;

-- Org-level cleanup configuration.
-- Bounds enforced at the API layer: 4h ≤ idle ≤ 60d, 1d ≤ retention ≤ 60d.
-- Defaults sit at the floor (4h idle) and the previous TTL retention (30d) so
-- new orgs are immediately within the bounds the PATCH endpoint will accept.
ALTER TABLE orgs ADD COLUMN subagent_idle_timeout_secs INTEGER NOT NULL DEFAULT 14400;
ALTER TABLE orgs ADD COLUMN subagent_archive_retention_days INTEGER NOT NULL DEFAULT 30;

-- Track WHY an api_key was revoked so restore can resurrect only auto-revoked keys.
ALTER TABLE api_keys ADD COLUMN revoked_reason TEXT;
