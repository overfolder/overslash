-- Restore the index set exactly as migrations 007 / 047 / 104 left it.
DROP INDEX IF EXISTS idx_audit_log_search_trgm;
DROP INDEX IF EXISTS idx_audit_log_org_resource_type;
DROP INDEX IF EXISTS idx_audit_log_org_action;

CREATE INDEX idx_audit_log_org ON audit_log (org_id, created_at DESC);
DROP INDEX IF EXISTS idx_audit_log_org_created_id;

CREATE INDEX idx_audit_log_tags ON audit_log USING GIN (tags);
CREATE INDEX idx_audit_log_impersonated_by
    ON audit_log(org_id, impersonated_by_identity_id)
    WHERE impersonated_by_identity_id IS NOT NULL;

ALTER TABLE audit_log DROP COLUMN owner_user_name;
ALTER TABLE audit_log DROP COLUMN actor_name;

-- The pg_trgm extension is left installed: other things may have come to
-- depend on it, and it costs nothing idle.
