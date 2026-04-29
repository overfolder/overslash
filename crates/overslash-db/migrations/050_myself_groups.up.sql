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

-- 3. Backfill: one Myself group per user-identity, plus grants on owned services.
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
        -- Create the Myself group (idempotent on the partial unique index).
        INSERT INTO groups (org_id, name, description, is_system, system_kind,
                            owner_identity_id, allow_raw_http)
        VALUES (
            r.org_id,
            'Myself: ' || COALESCE(r.email, r.name, r.identity_id::text),
            'Personal services and Layer-1 grants for this user',
            true,
            'self',
            r.identity_id,
            true
        )
        ON CONFLICT DO NOTHING
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

        -- Grant admin + auto_approve_reads on every service this user owns.
        INSERT INTO group_grants (group_id, service_instance_id, access_level,
                                  auto_approve_reads)
        SELECT self_id, si.id, 'admin', true
        FROM service_instances si
        WHERE si.org_id = r.org_id
          AND si.owner_identity_id = r.identity_id
        ON CONFLICT (group_id, service_instance_id) DO NOTHING;
    END LOOP;
END $$;
