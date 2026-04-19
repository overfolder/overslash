-- Drafts for OpenAPI import. A service_template row with status='draft' is
-- invisible to runtime lookups and listings but editable via the drafts
-- endpoints. On /promote it flips to 'active'. Drafts may hold a non-unique
-- key (empty or matching an active template the user plans to replace), so
-- the uniqueness indexes are re-scoped to status='active'.

ALTER TABLE service_templates
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('draft', 'active'));

-- Relax the existing uniqueness indexes to the active tier so drafts can
-- coexist with the templates they will replace.
DROP INDEX IF EXISTS idx_service_templates_org_key;
DROP INDEX IF EXISTS idx_service_templates_user_key;

CREATE UNIQUE INDEX idx_service_templates_org_key
    ON service_templates(org_id, key)
    WHERE owner_identity_id IS NULL AND status = 'active';

CREATE UNIQUE INDEX idx_service_templates_user_key
    ON service_templates(org_id, owner_identity_id, key)
    WHERE owner_identity_id IS NOT NULL AND status = 'active';

-- Support fast filtering of drafts when listing/cleaning up.
CREATE INDEX idx_service_templates_status ON service_templates(status);
