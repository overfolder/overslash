-- Invariant byoc_not_owner (D122).
-- A connection using a same-org, same-provider BYOC client that does not
-- belong to the connection's ceiling user (the user itself, or an agent's
-- owner). Mirrors byoc_binding::usable_byoc_pin; an agent with no owner has
-- no ceiling user, so nothing is usable for it.
WITH pins AS (
    SELECT c.id, c.org_id, b.id AS byoc_id, b.identity_id AS byoc_owner,
           CASE WHEN ci.kind = 'user' THEN ci.id ELSE ci.owner_id END AS ceiling
    FROM connections c
    JOIN byoc_credentials b ON b.id = c.byoc_credential_id
    JOIN identities ci ON ci.id = c.identity_id
    WHERE b.org_id = c.org_id
      AND b.provider_key = c.provider_key
)
SELECT p.org_id AS "org_id!",
       'connections' AS "subject_table!",
       p.id AS "subject_id!",
       'byoc_credential ' || p.byoc_id || ' owned by ' || p.byoc_owner
           || ' (ceiling user ' || COALESCE(p.ceiling::text, 'none') || ')' AS "detail!"
FROM pins p
WHERE p.ceiling IS NULL
   OR (p.byoc_owner <> p.ceiling
       AND NOT EXISTS (
           SELECT 1 FROM identities a
           WHERE a.id = p.byoc_owner
             AND a.kind <> 'user'
             AND a.owner_id = p.ceiling
       ))
ORDER BY p.org_id, p.id
