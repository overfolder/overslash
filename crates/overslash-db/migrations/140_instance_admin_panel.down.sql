ALTER TABLE users
    DROP COLUMN instance_admin_granted_by,
    DROP COLUMN instance_admin_granted_at;

DROP TABLE instance_audit_log;
