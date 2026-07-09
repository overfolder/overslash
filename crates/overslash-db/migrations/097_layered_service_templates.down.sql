-- Revert user_template_policy → allow_user_templates boolean.
ALTER TABLE orgs ADD COLUMN allow_user_templates BOOLEAN NOT NULL DEFAULT false;
UPDATE orgs SET allow_user_templates = (user_template_policy = 'full');
ALTER TABLE orgs DROP COLUMN user_template_policy;

-- Revert the layer columns. Any derived layers (openapi NULL) would violate the
-- restored NOT NULL, so the down path assumes they were removed/flattened first.
ALTER TABLE service_templates DROP CONSTRAINT IF EXISTS service_templates_layer_shape;
DROP INDEX IF EXISTS idx_service_templates_extends;
ALTER TABLE service_templates ALTER COLUMN openapi SET NOT NULL;
ALTER TABLE service_templates DROP COLUMN IF EXISTS delta;
ALTER TABLE service_templates DROP COLUMN IF EXISTS extends;
