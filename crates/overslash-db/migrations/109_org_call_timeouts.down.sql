ALTER TABLE orgs
    DROP CONSTRAINT orgs_call_timeout_bounds,
    DROP COLUMN max_call_timeout_ms,
    DROP COLUMN call_timeout_ms;
