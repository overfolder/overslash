DROP INDEX IF EXISTS org_idp_configs_one_default_per_org;

ALTER TABLE org_idp_configs DROP COLUMN is_default;
