DROP INDEX IF EXISTS idx_users_is_instance_admin;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_instance_admin_requires_overslash_idp;

ALTER TABLE users DROP COLUMN IF EXISTS is_instance_admin;
