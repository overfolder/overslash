DROP INDEX IF EXISTS idx_service_instances_pending_setup;

-- Rows first, or the narrowed CHECK fails on anything still mid-setup. `draft`
-- is the honest landing place: not callable, and the state a user would have
-- parked it in by hand before this migration existed.
UPDATE service_instances SET status = 'draft' WHERE status = 'pending_setup';

ALTER TABLE service_instances DROP CONSTRAINT service_instances_status_check;

ALTER TABLE service_instances ADD CONSTRAINT service_instances_status_check
    CHECK (status IN ('draft', 'active', 'archived'));
