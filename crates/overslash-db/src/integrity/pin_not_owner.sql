-- Invariant pin_not_owner (#723, D122).
-- A user-level instance pinned to a same-org connection that is neither the
-- owner's nor one of the owner's own agents'. Mirrors
-- group_ceiling::identity_belongs_to_user, the rule check_pin and
-- pinned_connection apply.
SELECT si.org_id AS "org_id!",
       'service_instances' AS "subject_table!",
       si.id AS "subject_id!",
       'connection ' || c.id || ' owned by ' || c.identity_id
           || ' (instance owner ' || si.owner_identity_id || ')' AS "detail!"
FROM service_instances si
JOIN connections c ON c.id = si.connection_id
WHERE si.owner_identity_id IS NOT NULL
  AND c.org_id = si.org_id
  AND c.identity_id <> si.owner_identity_id
  AND NOT EXISTS (
      SELECT 1 FROM identities a
      WHERE a.id = c.identity_id
        AND a.kind <> 'user'
        AND a.owner_id = si.owner_identity_id
  )
ORDER BY si.org_id, si.id
