ALTER TABLE orgs DROP COLUMN approval_auto_bubble_secs;

DROP INDEX IF EXISTS idx_approvals_resolver_pending;

ALTER TABLE approvals
    DROP COLUMN resolver_assigned_at,
    DROP COLUMN current_resolver_identity_id;
