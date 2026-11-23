-- Instance Admin panel (/instance): an instance-level audit trail and the
-- provenance of each instance-admin grant.
--
-- `audit_log` cannot hold these rows: its `org_id` is NOT NULL (granting
-- instance admin has no org) and it cascades on org delete (an instance
-- admin's history must outlive the org they acted on). So instance-admin
-- actions get their own table. Org-scoped actions (plan, trial, create) are
-- ALSO still written to the affected org's own audit_log, so that org's
-- members keep seeing them.

CREATE TABLE instance_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The instance admin who acted. SET NULL keeps the row when the user is
    -- deleted; `actor_email` is the name as of write time.
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    -- Deliberately no FK: the row must survive the org's deletion.
    -- `org_slug` is the slug as of write time. Both NULL for instance-only
    -- actions (granting/revoking instance admin).
    org_id UUID,
    org_slug TEXT,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_instance_audit_log_created
    ON instance_audit_log (created_at DESC, id DESC);
CREATE INDEX idx_instance_audit_log_actor
    ON instance_audit_log (actor_user_id, created_at DESC);
CREATE INDEX idx_instance_audit_log_org
    ON instance_audit_log (org_id, created_at DESC);

-- Who granted instance admin, and when. NULL on both = granted out-of-band
-- (psql bootstrap, or any grant made before this migration).
ALTER TABLE users
    ADD COLUMN instance_admin_granted_at TIMESTAMPTZ,
    ADD COLUMN instance_admin_granted_by UUID REFERENCES users(id) ON DELETE SET NULL;
