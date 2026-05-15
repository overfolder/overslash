ALTER TABLE org_idp_configs ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT false;

CREATE UNIQUE INDEX org_idp_configs_one_default_per_org
    ON org_idp_configs (org_id) WHERE is_default;
