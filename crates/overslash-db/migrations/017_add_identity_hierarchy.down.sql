DROP INDEX IF EXISTS idx_identities_owner;
DROP INDEX IF EXISTS idx_identities_parent;

ALTER TABLE identities DROP COLUMN inherit_permissions;
ALTER TABLE identities DROP COLUMN owner_id;
ALTER TABLE identities DROP COLUMN depth;
ALTER TABLE identities DROP COLUMN parent_id;

ALTER TABLE identities DROP CONSTRAINT identities_kind_check;
ALTER TABLE identities ADD CONSTRAINT identities_kind_check
    CHECK (kind IN ('user', 'agent'));
