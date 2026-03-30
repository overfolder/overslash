-- Permission rule expiry
DROP INDEX IF EXISTS idx_permission_rules_expires;
ALTER TABLE permission_rules DROP COLUMN IF EXISTS expires_at;

-- Approval bubbling columns
ALTER TABLE approvals DROP COLUMN IF EXISTS grant_to;
ALTER TABLE approvals DROP COLUMN IF EXISTS can_be_handled_by;
ALTER TABLE approvals DROP COLUMN IF EXISTS gap_identity_id;

-- Identity hierarchy columns
DROP INDEX IF EXISTS idx_identities_owner;
DROP INDEX IF EXISTS idx_identities_parent;
ALTER TABLE identities DROP COLUMN IF EXISTS ttl;
ALTER TABLE identities DROP COLUMN IF EXISTS max_sub_depth;
ALTER TABLE identities DROP COLUMN IF EXISTS can_create_sub;
ALTER TABLE identities DROP COLUMN IF EXISTS inherit_permissions;
ALTER TABLE identities DROP COLUMN IF EXISTS depth;
ALTER TABLE identities DROP COLUMN IF EXISTS owner_id;
ALTER TABLE identities DROP COLUMN IF EXISTS parent_id;

ALTER TABLE identities DROP CONSTRAINT identities_kind_check;
ALTER TABLE identities ADD CONSTRAINT identities_kind_check
    CHECK (kind IN ('user', 'agent'));
DELETE FROM identities WHERE kind = 'subagent';
