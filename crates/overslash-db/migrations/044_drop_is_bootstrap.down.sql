-- Restore the pre-042 shape. Rows re-created by running up twice will lose
-- which were originally bootstrap; that distinction was never load-bearing
-- for access control, so the default value is safe.
ALTER TABLE user_org_memberships
    ADD COLUMN IF NOT EXISTS is_bootstrap BOOLEAN NOT NULL DEFAULT false;
