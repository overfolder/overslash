DROP VIEW IF EXISTS effective_identity_groups;

ALTER TABLE org_idp_configs
    DROP COLUMN group_sync_enabled,
    DROP COLUMN group_claim;

DROP TABLE IF EXISTS group_directory_sources;
DROP TABLE IF EXISTS identity_directory_groups;
DROP TABLE IF EXISTS directory_groups;
