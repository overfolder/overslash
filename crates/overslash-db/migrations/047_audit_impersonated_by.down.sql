DROP INDEX IF EXISTS idx_audit_log_impersonated_by;
ALTER TABLE audit_log DROP COLUMN impersonated_by_identity_id;
