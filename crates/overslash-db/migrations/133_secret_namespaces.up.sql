-- Migration 133: secrets are namespaced per user; bindings are qualified paths.
--
-- Until now `(org_id, name)` was unique and every lookup — bind time and
-- call time — went by org + name, so any member could bind (and execute
-- with) another member's secret just by naming it. `owner_identity_id`
-- (migration 064) only gated visibility.
--
-- From here a secret lives in exactly one namespace:
--   * a user's vault  — owner_identity_id = that user's identity
--   * the org vault   — owner_identity_id IS NULL (admin-written)
-- and every binding (service_instances.secret_name / credentials values)
-- is a qualified path: `org/<name>` or `<user identity uuid>/<name>`.
-- See SecretPath in overslash-core.

-- 1. Agent/sub_agent-owned secrets move to their owner user: the namespace
--    is the ceiling user (same move 086 made for connections). Names are
--    still org-unique at this point, so this cannot collide.
UPDATE secrets s
SET owner_identity_id = i.owner_id, updated_at = now()
FROM identities i
WHERE s.owner_identity_id = i.id
  AND i.kind <> 'user'
  AND i.owner_id IS NOT NULL;

DO $$
DECLARE r record;
BEGIN
    FOR r IN
        SELECT s.org_id, s.name, s.owner_identity_id
        FROM secrets s JOIN identities i ON i.id = s.owner_identity_id
        WHERE i.kind <> 'user'
    LOOP
        RAISE NOTICE 'secret % in org % is still owned by non-user identity % (no owner_id)',
            r.name, r.org_id, r.owner_identity_id;
    END LOOP;
END $$;

-- 2. Org credentials move to the org vault. Admins wrote these under their
--    own identity, but they are org-wide by meaning: org OAuth app
--    credentials, and the defaults that `secret_source: org` schemes fall
--    back to (the shipped one is email.yaml's `overfwd_gateway_key`; DB
--    templates may declare more).
UPDATE secrets s
SET owner_identity_id = NULL, updated_at = now()
WHERE s.owner_identity_id IS NOT NULL
  AND (
    s.name ~ '^OAUTH_[A-Z0-9_]+_CLIENT_(ID|SECRET)$'
    OR s.name = 'overfwd_gateway_key'
    OR EXISTS (
        SELECT 1
        FROM service_templates t,
             jsonb_each(COALESCE(t.openapi -> 'components' -> 'securitySchemes', '{}'::jsonb)) sch
        WHERE t.org_id = s.org_id
          AND jsonb_typeof(sch.value) = 'object'
          AND COALESCE(sch.value ->> 'x-overslash-secret_source', sch.value ->> 'secret_source') = 'org'
          AND COALESCE(sch.value ->> 'x-overslash-default_secret_name', sch.value ->> 'default_secret_name') = s.name
    )
  );

-- 3. Qualify every existing binding against the CURRENT owner of the
--    (still org-unique) name. A name nobody has filled yet qualifies into
--    the instance owner's vault, or the org vault for org-level instances.
CREATE FUNCTION pg_temp.qualify_secret(p_org uuid, p_inst_owner uuid, v text) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN v IS NULL OR v = '' THEN v
        ELSE COALESCE(
            (SELECT COALESCE(s.owner_identity_id::text, 'org') || '/' || v
               FROM secrets s
              WHERE s.org_id = p_org AND s.name = v),
            COALESCE(p_inst_owner::text, 'org') || '/' || v)
    END
$$;

UPDATE service_instances si
SET secret_name = pg_temp.qualify_secret(si.org_id, si.owner_identity_id, si.secret_name),
    credentials = COALESCE(
        (SELECT jsonb_object_agg(e.key, pg_temp.qualify_secret(si.org_id, si.owner_identity_id, e.value))
           FROM jsonb_each_text(si.credentials) AS e(key, value)),
        '{}'::jsonb)
WHERE si.secret_name IS NOT NULL OR si.credentials <> '{}'::jsonb;

-- 4. Report — never rewrite — user-level instances bound into someone
--    else's vault. They stay dangling; the runtime refuses them with a
--    "rebind it" envelope.
DO $$
DECLARE r record;
BEGIN
    FOR r IN
        SELECT si.id, si.org_id, si.name, si.owner_identity_id, b.value AS path
        FROM service_instances si,
             LATERAL (
                 SELECT si.secret_name AS value
                 UNION ALL
                 SELECT e.value FROM jsonb_each_text(si.credentials) e
             ) b
        WHERE si.owner_identity_id IS NOT NULL
          AND b.value IS NOT NULL
          AND b.value NOT LIKE 'org/%'
          AND b.value NOT LIKE si.owner_identity_id::text || '/%'
    LOOP
        RAISE NOTICE 'cross-user binding: instance % (%) in org % owned by % is bound to %',
            r.name, r.id, r.org_id, r.owner_identity_id, r.path;
    END LOOP;
END $$;

-- 5. Uniqueness is per namespace. NULLS NOT DISTINCT makes the org vault
--    (NULL owner) one namespace, so one constraint and one ON CONFLICT
--    target cover both.
ALTER TABLE secrets DROP CONSTRAINT secrets_org_id_name_key;
ALTER TABLE secrets ADD CONSTRAINT secrets_org_owner_name_key
    UNIQUE NULLS NOT DISTINCT (org_id, owner_identity_id, name);
CREATE INDEX idx_secrets_org_name ON secrets (org_id, name);

-- 6. Deleting a user deletes their vault. SET NULL would silently promote
--    their secrets into the org vault (or collide with an org secret).
ALTER TABLE secrets DROP CONSTRAINT secrets_owner_identity_id_fkey;
ALTER TABLE secrets ADD CONSTRAINT secrets_owner_identity_id_fkey
    FOREIGN KEY (owner_identity_id) REFERENCES identities(id) ON DELETE CASCADE;

COMMENT ON COLUMN secrets.owner_identity_id IS
    'Namespace: the owning user identity, or NULL for the org-wide vault. Unique with (org_id, name).';
COMMENT ON COLUMN service_instances.credentials IS
    'Per-scheme secret bindings: {securityScheme key -> secret path}. A path is org/<name> or <user identity uuid>/<name> (SecretPath). Names only, never values. Empty map falls back to legacy secret_name for the sole instance-source scheme.';
