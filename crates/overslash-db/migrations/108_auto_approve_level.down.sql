ALTER TABLE group_grants
  DROP CONSTRAINT group_grants_auto_approve_within_ceiling,
  DROP CONSTRAINT group_grants_auto_approve_level_valid,
  DROP COLUMN auto_approve_level;

COMMENT ON COLUMN group_grants.auto_approve_reads IS NULL;
