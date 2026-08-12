-- Destructive by necessity: `approval_id` cannot return to NOT NULL while
-- direct-async rows exist, and those rows have no approval to point at. In
-- practice this migration is forward-only in production; the down path exists
-- for local rollback.

ALTER TABLE approvals
    DROP COLUMN execution_mode;

DELETE FROM executions WHERE approval_id IS NULL;

DROP INDEX IF EXISTS idx_executions_identity_recent;
DROP INDEX IF EXISTS idx_executions_async_lease;
DROP INDEX IF EXISTS idx_executions_async_queue;

DROP INDEX idx_executions_approval_id;
CREATE UNIQUE INDEX idx_executions_approval_id ON executions (approval_id);

ALTER TABLE executions
    DROP CONSTRAINT executions_attempts_nonneg,
    DROP CONSTRAINT executions_has_origin;

ALTER TABLE executions
    DROP COLUMN client_ip,
    DROP COLUMN description,
    DROP COLUMN template_key,
    DROP COLUMN render_verbose,
    DROP COLUMN cancel_requested,
    DROP COLUMN attempts,
    DROP COLUMN worker_id,
    DROP COLUMN lease_expires_at,
    DROP COLUMN service_instance_id,
    DROP COLUMN service_key,
    DROP COLUMN request,
    DROP COLUMN identity_id;

ALTER TABLE executions
    ALTER COLUMN approval_id SET NOT NULL;
