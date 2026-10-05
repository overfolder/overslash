-- Invariant pin_cross_org (#723).
-- A user-level instance pinned to a connection that lives in another org.
-- (Org-level pins are counted by pin_on_org_instance instead.)
SELECT si.org_id AS "org_id!",
       'service_instances' AS "subject_table!",
       si.id AS "subject_id!",
       'connection ' || c.id || ' in org ' || c.org_id AS "detail!"
FROM service_instances si
JOIN connections c ON c.id = si.connection_id
WHERE si.owner_identity_id IS NOT NULL
  AND c.org_id <> si.org_id
ORDER BY si.org_id, si.id
