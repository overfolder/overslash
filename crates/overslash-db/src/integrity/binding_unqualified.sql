-- Invariant binding_unqualified (D119, migration 133).
-- A binding that is neither `org/<name>` nor `<user identity id>/<name>`:
-- a bare name or a handle. Migration 133 qualified every binding, and every
-- writer goes through BindingWriter, so this should be empty.
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
SELECT org_id AS "org_id!",
       'service_instances' AS "subject_table!",
       id AS "subject_id!",
       slot || ' = ' || path AS "detail!"
FROM qualified
WHERE ns IS NULL
  AND path !~ '^org/.'
ORDER BY org_id, id, slot
