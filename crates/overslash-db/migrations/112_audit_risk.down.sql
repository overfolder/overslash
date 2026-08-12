DROP INDEX IF EXISTS idx_audit_log_org_risk;
ALTER TABLE audit_log DROP COLUMN risk;
