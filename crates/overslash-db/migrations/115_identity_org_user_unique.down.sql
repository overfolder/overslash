-- The step-1 detach is not reversible: once `user_id` is NULL there is no
-- record of which human the losing duplicate used to claim. That is the point
-- of the up-migration, and re-forking those links on a rollback would be worse
-- than leaving them detached.

DROP INDEX IF EXISTS identities_org_user_unique;

CREATE INDEX IF NOT EXISTS idx_identities_email_lookup
    ON identities (email)
    WHERE email IS NOT NULL;
