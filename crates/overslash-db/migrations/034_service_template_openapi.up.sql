-- Flip service_templates.auth + actions JSONB columns to a single openapi JSONB
-- column holding the full OpenAPI 3.1 document. Overslash is unreleased so no
-- data migration is needed.
ALTER TABLE service_templates DROP COLUMN auth;
ALTER TABLE service_templates DROP COLUMN actions;
ALTER TABLE service_templates ADD COLUMN openapi JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE service_templates ALTER COLUMN openapi DROP DEFAULT;
