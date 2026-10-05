-- Invariant binding_foreign_user_vault (D119, D122).
-- A user-level instance bound into a *colleague's* vault. The read rule
-- (secret_paths::readable_instance_binding) refuses these at call time, so
-- the instance silently runs unbound; migration 133 RAISE NOTICE'd the ones
-- it found and left them in place.
WITH bindings AS (
    -- Every stored secret binding: the legacy `secret_name` plus each
    -- `credentials` slot. Paths are `org/<name>` or `<user identity id>/<name>`.
    SELECT si.id, si.org_id, si.owner_identity_id, b.slot, b.path
    FROM service_instances si
    CROSS JOIN LATERAL (
        SELECT 'secret_name'::text AS slot, si.secret_name AS path
        UNION ALL
        SELECT 'credentials.' || c.key, c.value
        FROM jsonb_each_text(
            CASE WHEN jsonb_typeof(si.credentials) = 'object'
                 THEN si.credentials ELSE '{}'::jsonb END
        ) c
    ) b
    WHERE b.path IS NOT NULL AND b.path <> ''
),
qualified AS (
    -- Bindings into a user vault, with the namespace parsed out. The CASE
    -- keeps the cast from ever seeing a non-uuid prefix.
    SELECT bindings.*,
           CASE WHEN path ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/.'
                THEN substring(path FROM 1 FOR 36)::uuid END AS ns
    FROM bindings
)
SELECT q.org_id AS "org_id!",
       'service_instances' AS "subject_table!",
       q.id AS "subject_id!",
       q.slot || ' = ' || q.path || ' (owner ' || q.owner_identity_id || ')' AS "detail!"
FROM qualified q
WHERE q.owner_identity_id IS NOT NULL
  AND q.ns <> q.owner_identity_id
  AND EXISTS (
      SELECT 1 FROM identities i
      WHERE i.id = q.ns AND i.org_id = q.org_id AND i.kind = 'user'
  )
ORDER BY q.org_id, q.id, q.slot
