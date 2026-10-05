-- Invariant secret_owner_not_user (D119, migration 133).
-- A live secret in an agent's vault. Vaults belong to users and the org;
-- migration 133 re-homed agents' secrets to their owner user and NOTICE'd the
-- ones it could not (agents with no owner_id).
SELECT s.org_id AS "org_id!",
       'secrets' AS "subject_table!",
       s.id AS "subject_id!",
       'owned by ' || i.kind || ' ' || i.id AS "detail!"
FROM secrets s
JOIN identities i ON i.id = s.owner_identity_id
WHERE s.deleted_at IS NULL
  AND i.org_id = s.org_id
  AND i.kind <> 'user'
ORDER BY s.org_id, s.id
