ALTER TABLE orgs DROP COLUMN IF EXISTS trial_ends_at;

-- Revert the plan CHECK to its 052 shape. Any rows left on 'trial' would
-- violate this; the down path assumes they were migrated off first.
ALTER TABLE orgs DROP CONSTRAINT IF EXISTS orgs_plan_check;
ALTER TABLE orgs
    ADD CONSTRAINT orgs_plan_check CHECK (plan IN ('standard', 'free_unlimited'));
