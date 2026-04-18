ALTER TABLE service_templates DROP COLUMN openapi;
ALTER TABLE service_templates ADD COLUMN auth JSONB NOT NULL DEFAULT '[]';
ALTER TABLE service_templates ADD COLUMN actions JSONB NOT NULL DEFAULT '{}';
