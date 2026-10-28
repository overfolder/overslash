-- Per-org default expiry for "Allow & Remember" rules.
--
-- Before this, a remembered rule lived forever unless the approver changed the
-- expiry picker, and an API/MCP resolve that omitted `ttl` minted a permanent
-- rule. Forever is the riskiest choice to make by default: a standing grant
-- nobody revisits. Orgs now pick the default, and it starts at 7 days.
--
-- NULL = forever (no expiry), the same Option::None the rule's own
-- `expires_at` uses. The column DEFAULT backfills every existing org to 7 days
-- on purpose — the safer default should reach orgs that never opted in.
--
-- The 60s..365d bounds mirror the resolver's own ttl cap, so a default can
-- never mint a rule an explicit `ttl` could not.

ALTER TABLE orgs
    ADD COLUMN default_remember_ttl_secs INTEGER DEFAULT 604800;

ALTER TABLE orgs
    ADD CONSTRAINT orgs_default_remember_ttl_bounds CHECK (
        default_remember_ttl_secs IS NULL
     OR default_remember_ttl_secs BETWEEN 60 AND 31536000
    );

COMMENT ON COLUMN orgs.default_remember_ttl_secs IS
    'Default expiry in seconds for rules written by Allow & Remember when the resolver does not pass a ttl. NULL = forever.';
