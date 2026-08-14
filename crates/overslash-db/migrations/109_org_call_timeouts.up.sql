-- Per-org upstream call timeouts (D56).
--
-- Before this, how long an action call could wait on an upstream was a single
-- global env var applied only to approval replays; the inline call path had no
-- timeout at all and simply rode until the load balancer cut the connection at
-- 120s. An org whose Metabase aggregations legitimately take 90s had no way to
-- say so, and an org that wanted to bound its agents had no way to say that
-- either.
--
-- Two columns, because one cannot do both jobs. As a default only, a per-call
-- `timeout_ms` would escape governance entirely; as a ceiling only, every call
-- would run at the org maximum with no sane middle. They answer different
-- questions:
--
--   call_timeout_ms      what should our calls get when nobody says otherwise
--   max_call_timeout_ms  what is the worst an agent may hold a connection for
--
-- Both NULL = inherit the deployment defaults (CALL_TIMEOUT_MS /
-- CALL_TIMEOUT_MAX_MS). NULL rather than a sentinel so "inherit" is the same
-- Option::None the template and per-call layers already use, and so raising a
-- deployment default reaches every org that never opted out.
--
-- The 1s..600s bounds are structural sanity, not policy: the real ceiling is
-- CALL_TIMEOUT_MAX_MS, which is enforced in the resolver and is itself pinned
-- below the deployment's own request cap. This constraint only keeps a typo
-- (`60` meaning minutes, `600000000` meaning nothing) out of the table.

ALTER TABLE orgs
    ADD COLUMN call_timeout_ms     INTEGER,
    ADD COLUMN max_call_timeout_ms INTEGER;

ALTER TABLE orgs
    ADD CONSTRAINT orgs_call_timeout_bounds CHECK (
        (call_timeout_ms     IS NULL OR call_timeout_ms     BETWEEN 1000 AND 600000)
    AND (max_call_timeout_ms IS NULL OR max_call_timeout_ms BETWEEN 1000 AND 600000)
    AND (call_timeout_ms IS NULL
      OR max_call_timeout_ms IS NULL
      OR call_timeout_ms <= max_call_timeout_ms)
    );

COMMENT ON COLUMN orgs.call_timeout_ms IS
    'Default upstream timeout in ms for action calls in this org. NULL inherits the deployment default (CALL_TIMEOUT_MS). Overridden per template action and per call.';

COMMENT ON COLUMN orgs.max_call_timeout_ms IS
    'Ceiling on any resolved call timeout in this org, in ms. NULL inherits CALL_TIMEOUT_MAX_MS. A caller asking for more is rejected; a template or org default above it is clamped.';
