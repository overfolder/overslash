DROP TABLE IF EXISTS enabled_global_templates;
ALTER TABLE orgs
    DROP COLUMN IF EXISTS allow_user_templates,
    DROP COLUMN IF EXISTS global_templates_enabled;
