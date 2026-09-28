DROP TABLE IF EXISTS org_google_directory_configs;

DELETE FROM directory_groups WHERE source = 'google_directory';
ALTER TABLE directory_groups DROP CONSTRAINT directory_groups_source_check;
ALTER TABLE directory_groups
    ADD CONSTRAINT directory_groups_source_check
    CHECK (source IN ('oidc_claim'));
