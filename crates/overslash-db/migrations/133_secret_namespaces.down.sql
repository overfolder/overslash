-- Reverse of 133. Restoring UNIQUE (org_id, name) FAILS LOUDLY if two
-- namespaces now hold the same name — resolve those by hand first. Agent
-- re-homing and the org-vault move are not reversed (the original owners
-- are not retained); owners stay valid under the old model.

COMMENT ON COLUMN service_instances.credentials IS
  'Per-scheme secret bindings: {securityScheme key -> secret NAME in the org vault}. Names only, never values. Empty map falls back to legacy secret_name for the sole instance-source scheme.';
COMMENT ON COLUMN secrets.owner_identity_id IS NULL;

ALTER TABLE secrets DROP CONSTRAINT secrets_owner_identity_id_fkey;
ALTER TABLE secrets ADD CONSTRAINT secrets_owner_identity_id_fkey
    FOREIGN KEY (owner_identity_id) REFERENCES identities(id) ON DELETE SET NULL;

DROP INDEX IF EXISTS idx_secrets_org_name;
ALTER TABLE secrets DROP CONSTRAINT secrets_org_owner_name_key;
ALTER TABLE secrets ADD CONSTRAINT secrets_org_id_name_key UNIQUE (org_id, name);

-- Strip the namespace prefix from bindings: `org/<name>` / `<uuid>/<name>`.
CREATE FUNCTION pg_temp.unqualify_secret(v text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE
        WHEN v ~ '^org/.' THEN substr(v, 5)
        WHEN v ~ '^[0-9a-fA-F-]{36}/.' THEN substr(v, 38)
        ELSE v
    END
$$;

UPDATE service_instances si
SET secret_name = pg_temp.unqualify_secret(si.secret_name),
    credentials = COALESCE(
        (SELECT jsonb_object_agg(e.key, pg_temp.unqualify_secret(e.value))
           FROM jsonb_each_text(si.credentials) AS e(key, value)),
        '{}'::jsonb)
WHERE si.secret_name IS NOT NULL OR si.credentials <> '{}'::jsonb;
