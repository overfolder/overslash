DROP INDEX IF EXISTS idx_audit_log_tags;
ALTER TABLE audit_log  DROP COLUMN tags;
ALTER TABLE executions DROP COLUMN tags;
ALTER TABLE approvals  DROP COLUMN tags;
