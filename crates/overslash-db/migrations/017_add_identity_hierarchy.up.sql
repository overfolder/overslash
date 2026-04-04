-- Add parent/child identity hierarchy with depth tracking.
-- Enables User → Agent → SubAgent relationships per SPEC.md §4.

-- 1. Expand kind to include sub_agent
ALTER TABLE identities DROP CONSTRAINT identities_kind_check;
ALTER TABLE identities ADD CONSTRAINT identities_kind_check
    CHECK (kind IN ('user', 'agent', 'sub_agent'));

-- 2. Hierarchy columns
ALTER TABLE identities ADD COLUMN parent_id UUID REFERENCES identities(id) ON DELETE CASCADE;
ALTER TABLE identities ADD COLUMN depth INTEGER NOT NULL DEFAULT 0;
ALTER TABLE identities ADD COLUMN owner_id UUID REFERENCES identities(id) ON DELETE SET NULL;
ALTER TABLE identities ADD COLUMN inherit_permissions BOOLEAN NOT NULL DEFAULT false;

-- 3. Indexes for hierarchy traversal
CREATE INDEX idx_identities_parent ON identities(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX idx_identities_owner ON identities(owner_id) WHERE owner_id IS NOT NULL;
