-- Org-level billing tier. `standard` is the default for every org (the existing
-- behavior: rate-limited, Team orgs go through Stripe). `free_unlimited` is a
-- courtesy tier set out-of-band by an operator via `psql`; rows with this plan
-- bypass rate limits entirely and never need a Stripe subscription. There is
-- no API/UI to flip this — DB is the only control surface.
--
-- CHECK rather than ENUM so adding tiers later is a one-liner.

ALTER TABLE orgs
    ADD COLUMN plan TEXT NOT NULL DEFAULT 'standard'
        CHECK (plan IN ('standard', 'free_unlimited'));

-- Partial index keeps writes cheap (only non-default rows are indexed).
CREATE INDEX idx_orgs_plan ON orgs (plan) WHERE plan != 'standard';
