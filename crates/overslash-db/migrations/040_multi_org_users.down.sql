-- Reverse 040_multi_org_users.up.sql. Drops the backfilled data along with
-- the new tables. Existing identities rows are preserved; only the user_id
-- column and FK are dropped from them.

ALTER TABLE identities DROP CONSTRAINT IF EXISTS identities_user_id_fkey;
DROP INDEX IF EXISTS idx_identities_user;
ALTER TABLE identities DROP COLUMN IF EXISTS user_id;

ALTER TABLE orgs DROP COLUMN IF EXISTS is_personal;

DROP INDEX IF EXISTS idx_memberships_org;
DROP TABLE IF EXISTS user_org_memberships;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_personal_org_id_fkey;
DROP INDEX IF EXISTS idx_users_personal_org;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS users_overslash_idp_unique;
DROP TABLE IF EXISTS users;
