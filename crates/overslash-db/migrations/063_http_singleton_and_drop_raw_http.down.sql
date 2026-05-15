-- Reverse migration 063: re-add the `allow_raw_http` flag and drop the
-- system-managed `http` service instance + its grants.

ALTER TABLE groups ADD COLUMN allow_raw_http BOOLEAN NOT NULL DEFAULT false;

-- Repopulate the flag from any group that holds a grant on the http instance
-- (regardless of access level — the flag was binary, so any access level
-- collapses to true).
UPDATE groups g
   SET allow_raw_http = true
  FROM group_grants gg
  JOIN service_instances si
    ON si.id = gg.service_instance_id
 WHERE gg.group_id = g.id
   AND si.name = 'http'
   AND si.is_system = true;

-- Drop grants pointing at the http instance, then the instance rows.
DELETE FROM group_grants
 WHERE service_instance_id IN (
     SELECT id FROM service_instances WHERE name = 'http' AND is_system = true
 );

DELETE FROM service_instances WHERE name = 'http' AND is_system = true;
