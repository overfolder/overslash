ALTER TABLE identities ADD COLUMN parent_id UUID REFERENCES identities(id) ON DELETE CASCADE;
ALTER TABLE identities ADD COLUMN depth INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_identities_parent ON identities(parent_id) WHERE parent_id IS NOT NULL;
