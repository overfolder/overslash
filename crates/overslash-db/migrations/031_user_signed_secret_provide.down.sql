DROP INDEX IF EXISTS idx_secret_versions_provisioned_by;

ALTER TABLE secret_versions
    DROP COLUMN IF EXISTS provisioned_by_user_id;

ALTER TABLE secret_requests
    DROP COLUMN IF EXISTS require_user_session;

ALTER TABLE orgs
    DROP COLUMN IF EXISTS allow_unsigned_secret_provide;
