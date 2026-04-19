DROP INDEX IF EXISTS idx_service_templates_status;
DROP INDEX IF EXISTS idx_service_templates_org_key;
DROP INDEX IF EXISTS idx_service_templates_user_key;

CREATE UNIQUE INDEX idx_service_templates_org_key
    ON service_templates(org_id, key) WHERE owner_identity_id IS NULL;
CREATE UNIQUE INDEX idx_service_templates_user_key
    ON service_templates(org_id, owner_identity_id, key) WHERE owner_identity_id IS NOT NULL;

ALTER TABLE service_templates DROP COLUMN status;
