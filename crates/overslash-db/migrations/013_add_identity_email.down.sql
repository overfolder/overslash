DROP INDEX IF EXISTS idx_identities_user_email;
DROP INDEX IF EXISTS idx_identities_email;
ALTER TABLE identities DROP COLUMN IF EXISTS email;
