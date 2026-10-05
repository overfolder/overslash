-- Invariant pin_on_org_instance (#723).
-- An org-level instance (no owner) with a pinned connection. A connection is
-- one person's grant; connection_binding::validate_connection_binding refuses
-- to pin one to an instance every member can call.
SELECT si.org_id AS "org_id!",
       'service_instances' AS "subject_table!",
       si.id AS "subject_id!",
       'connection ' || si.connection_id AS "detail!"
FROM service_instances si
WHERE si.owner_identity_id IS NULL
  AND si.connection_id IS NOT NULL
ORDER BY si.org_id, si.id
