-- Myself groups: collapse the user-level service abstraction into the group model.
--
-- Adds a typed `system_kind` column on groups (replacing brittle name='Everyone'/'Admins'
-- lookups) and an `owner_identity_id` column for the new per-user "self" group kind.
-- Backfills:
--   1. system_kind for existing Everyone/Admins rows
--   2. one Myself group per kind='user' identity (with the user as the sole member)
--   3. admin + auto_approve_reads grants on every service_instance the user owns
--
-- After this migration the user-owned-service permission bypass becomes redundant —
-- owner access flows through the standard ceiling via the Myself grant. The bypass
-- itself is removed in application code (actions.rs).

-- 1. Typed system-group kinds.
ALTER TABLE groups ADD COLUMN system_kind TEXT
    CHECK (system_kind IN ('everyone', 'admins', 'self'));

UPDATE groups SET system_kind = 'everyone'
    WHERE is_system = true AND name = 'Everyone';
UPDATE groups SET system_kind = 'admins'
    WHERE is_system = true AND name = 'Admins';

-- 2. Myself groups carry the identity they shadow.
ALTER TABLE groups ADD COLUMN owner_identity_id UUID
    REFERENCES identities(id) ON DELETE CASCADE;

-- Exactly one Myself group per (org, user-identity).
CREATE UNIQUE INDEX idx_groups_self_per_user
    ON groups(org_id, owner_identity_id)
    WHERE system_kind = 'self';

-- owner_identity_id is set iff system_kind = 'self'.
ALTER TABLE groups ADD CONSTRAINT groups_owner_only_for_self
    CHECK ((system_kind = 'self') = (owner_identity_id IS NOT NULL));

-- 3. Re-home services owned by agent/sub-agent identities to their owner-user.
-- Pre-PR `create_service` defaulted user_level=true for any identity-bound key,
-- which set `owner_identity_id` directly on the calling agent — fine under the
-- old user-owned-service bypass, broken once the bypass is removed (the agent's
-- ceiling user is the owner-user, who has no Myself grant on the service).
-- Re-pointing to `identities.owner_id` puts the service back in the user's
-- namespace where the new model expects it; the agent loses no access because
-- its ceiling resolves through the owner-user.
UPDATE service_instances si
   SET owner_identity_id = i.owner_id, updated_at = now()
  FROM identities i
 WHERE si.owner_identity_id = i.id
   AND i.kind IN ('agent', 'sub_agent')
   AND i.owner_id IS NOT NULL;

-- 4. Backfill: one Myself group per user-identity, plus grants on owned services.
--
-- Two unique constraints can fire on the INSERT below: the partial
-- `idx_groups_self_per_user (org_id, owner_identity_id) WHERE system_kind = 'self'`
-- (which is the legitimate idempotency case, two backfill runs of the same user)
-- and `groups_org_id_name_key (org_id, name)` (which fires when two distinct
-- users in the same org share an email or name — `identities.email`/`name` are
-- not unique per migration 043). To make the name unique by construction we
-- suffix with the first 8 chars of the identity uuid; the dashboard hides this
-- detail behind the "Myself" label. The conflict target on the partial index is
-- named explicitly so any *other* unique violation surfaces as a hard error
-- rather than being silently absorbed.
DO $$
DECLARE
    r RECORD;
    self_id UUID;
BEGIN
    FOR r IN
        SELECT id AS identity_id, org_id, name, email
        FROM identities
        WHERE kind = 'user' AND archived_at IS NULL
    LOOP
        INSERT INTO groups (org_id, name, description, is_system, system_kind,
                            owner_identity_id, allow_raw_http)
        VALUES (
            r.org_id,
            'Myself: ' || COALESCE(r.email, r.name, '') ||
                ' (' || left(r.identity_id::text, 8) || ')',
            'Personal services and Layer-1 grants for this user',
            true,
            'self',
            r.identity_id,
            true
        )
        ON CONFLICT (org_id, owner_identity_id) WHERE system_kind = 'self'
        DO NOTHING
        RETURNING id INTO self_id;

        IF self_id IS NULL THEN
            SELECT id INTO self_id FROM groups
            WHERE org_id = r.org_id
              AND owner_identity_id = r.identity_id
              AND system_kind = 'self';
        END IF;

        -- Add the user as the sole member.
        INSERT INTO identity_groups (identity_id, group_id)
        VALUES (r.identity_id, self_id)
        ON CONFLICT DO NOTHING;

        -- Grant admin + auto_approve_reads on every service this user owns
        -- (including services just re-homed from their agents in step 3).
        INSERT INTO group_grants (group_id, service_instance_id, access_level,
                                  auto_approve_reads)
        SELECT self_id, si.id, 'admin', true
        FROM service_instances si
        WHERE si.org_id = r.org_id
          AND si.owner_identity_id = r.identity_id
        ON CONFLICT (group_id, service_instance_id) DO NOTHING;
    END LOOP;
END $$;
