ALTER TABLE orgs
    DROP CONSTRAINT orgs_default_remember_ttl_bounds,
    DROP COLUMN default_remember_ttl_secs;
