-- Identity hierarchy columns
ALTER TABLE identities DROP CONSTRAINT identities_kind_check;
ALTER TABLE identities ADD CONSTRAINT identities_kind_check
    CHECK (kind IN ('user', 'agent', 'subagent'));

ALTER TABLE identities ADD COLUMN parent_id UUID REFERENCES identities(id) ON DELETE CASCADE;
ALTER TABLE identities ADD COLUMN owner_id UUID REFERENCES identities(id) ON DELETE SET NULL;
ALTER TABLE identities ADD COLUMN depth INTEGER NOT NULL DEFAULT 0;
ALTER TABLE identities ADD COLUMN inherit_permissions BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE identities ADD COLUMN can_create_sub BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE identities ADD COLUMN max_sub_depth INTEGER;
ALTER TABLE identities ADD COLUMN ttl INTERVAL;

CREATE INDEX idx_identities_parent ON identities(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX idx_identities_owner ON identities(owner_id) WHERE owner_id IS NOT NULL;

-- Approval bubbling columns
ALTER TABLE approvals ADD COLUMN gap_identity_id UUID REFERENCES identities(id) ON DELETE CASCADE;
ALTER TABLE approvals ADD COLUMN can_be_handled_by UUID[] NOT NULL DEFAULT '{}';
ALTER TABLE approvals ADD COLUMN grant_to UUID REFERENCES identities(id) ON DELETE SET NULL;

-- Permission rule expiry
ALTER TABLE permission_rules ADD COLUMN expires_at TIMESTAMPTZ;

CREATE INDEX idx_permission_rules_expires ON permission_rules(expires_at)
    WHERE expires_at IS NOT NULL;
