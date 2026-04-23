-- Remove the "naked org identity" concept.
--
-- All admin/auth surfaces must be performed by a User or Agent. There is no
-- standalone org actor. This migration:
--   1. Adds `is_org_admin` to identities (User-only via CHECK).
--   2. Syncs the flag from existing membership in the system "Admins" group.
--   3. Auto-maps any api_keys with NULL identity_id → the org's earliest user
--      (which migration 023 already designated as the first admin), then
--      enforces NOT NULL and switches the FK to ON DELETE CASCADE.
--   4. Drops every BYOC credential with NULL identity_id, then enforces NOT NULL.
--   5. Drops the partial unique index that only existed to support NULL identity.

-- ── 1. is_org_admin column ──────────────────────────────────────────────
ALTER TABLE identities
    ADD COLUMN is_org_admin BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE identities
    ADD CONSTRAINT identities_is_org_admin_only_user
    CHECK (kind = 'user' OR is_org_admin = false);

-- ── 2. Backfill from the "Admins" system group ──────────────────────────
UPDATE identities i
   SET is_org_admin = true
  FROM identity_groups ig
  JOIN groups g ON g.id = ig.group_id
 WHERE ig.identity_id = i.id
   AND g.is_system = true
   AND g.name = 'Admins'
   AND i.kind = 'user';

-- ── 3. api_keys: map NULL identity → first user, then enforce NOT NULL ──
DO $$
DECLARE
    r RECORD;
    first_user_id UUID;
BEGIN
    FOR r IN SELECT DISTINCT org_id FROM api_keys WHERE identity_id IS NULL LOOP
        SELECT id INTO first_user_id
          FROM identities
         WHERE org_id = r.org_id AND kind = 'user'
         ORDER BY created_at ASC
         LIMIT 1;

        IF first_user_id IS NULL THEN
            -- No user in this org at all: revoke the orphan keys rather than
            -- inventing a synthetic identity. The bootstrap path will mint a
            -- fresh user + key the next time someone hits POST /v1/api-keys.
            UPDATE api_keys
               SET revoked_at = COALESCE(revoked_at, now()),
                   revoked_reason = COALESCE(revoked_reason, 'org_level_removed')
             WHERE org_id = r.org_id AND identity_id IS NULL;
        ELSE
            UPDATE api_keys
               SET identity_id = first_user_id
             WHERE org_id = r.org_id AND identity_id IS NULL;

            -- Make sure that user is also flagged as an admin (idempotent).
            UPDATE identities SET is_org_admin = true WHERE id = first_user_id;
        END IF;
    END LOOP;
END $$;

-- Any remaining NULLs are revoked (and therefore safe to leave NULL); but the
-- next ALTER requires every row to have a value, so DELETE the revoked orphans
-- — they cannot authenticate anyway.
DELETE FROM api_keys WHERE identity_id IS NULL;

ALTER TABLE api_keys
    ALTER COLUMN identity_id SET NOT NULL;

-- Switch FK from SET NULL → CASCADE so a hard-purged identity also drops its
-- keys (and the orphan-NULL race in the auth middleware can no longer arise).
ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_identity_id_fkey;
ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_identity_id_fkey
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE;

-- ── 4. byoc_credentials: drop NULL-identity rows, enforce NOT NULL ──────
DROP INDEX IF EXISTS byoc_credentials_org_provider_null_identity;

DELETE FROM byoc_credentials WHERE identity_id IS NULL;

ALTER TABLE byoc_credentials
    ALTER COLUMN identity_id SET NOT NULL;
