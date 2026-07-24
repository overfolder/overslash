-- Fold `org_invites` into `identities`.
--
-- A pending invite carried exactly the same information as a pre-created user
-- identity: (org, email, role, "has never signed in"). We now represent an
-- invited-but-not-yet-signed-in member as a `kind='user'` identity with
-- `external_id IS NULL`, so there is a single way to say "this person belongs
-- to this org" — created by an invite, by name-based impersonation, or adopted
-- by email at first sign-in.
--
-- This migration backfills each *pending* invite into that shape (identity +
-- Everyone/Myself groups, plus Admins + is_org_admin for admin invites) and
-- then drops the table. Accepted invites are historical only and are not
-- migrated — the members they admitted already have live identities.

-- 1. One user identity per pending invite that has no live user identity for
--    that (org, email) yet. `name` is the email local-part; `email` is stored
--    lower-cased (the source column already enforces lower-case).
WITH pending AS (
    SELECT i.org_id, i.email, i.role
    FROM org_invites i
    WHERE i.accepted_at IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM identities d
          WHERE d.org_id = i.org_id
            AND d.kind = 'user'
            AND lower(d.email) = i.email
            AND d.archived_at IS NULL
      )
)
INSERT INTO identities (org_id, name, kind, email)
SELECT org_id, split_part(email, '@', 1), 'user', email
FROM pending;

-- 2. Everyone-group membership for every freshly-created invite identity.
--    Match by (org, email, external_id IS NULL) — the rows this migration just
--    inserted are exactly the never-signed-in user identities.
INSERT INTO identity_groups (identity_id, group_id)
SELECT d.id, g.id
FROM identities d
JOIN groups g ON g.org_id = d.org_id AND g.system_kind = 'everyone'
WHERE d.kind = 'user'
  AND d.external_id IS NULL
  AND d.archived_at IS NULL
  AND EXISTS (
      SELECT 1 FROM org_invites i
      WHERE i.org_id = d.org_id AND i.email = lower(d.email) AND i.accepted_at IS NULL
  )
ON CONFLICT DO NOTHING;

-- 3. Per-identity Myself (self) group, mirroring `group::ensure_self_group`:
--    name suffixed with the first 8 hex chars of the identity id so the
--    (org_id, name) unique index cannot collide between look-alike members.
INSERT INTO groups (org_id, name, description, is_system, system_kind, owner_identity_id)
SELECT d.org_id,
       'Myself: ' || COALESCE(NULLIF(d.email, ''), d.name) || ' (' || substr(replace(d.id::text, '-', ''), 1, 8) || ')',
       'Personal services and Layer-1 grants for this user',
       true, 'self', d.id
FROM identities d
WHERE d.kind = 'user'
  AND d.external_id IS NULL
  AND d.archived_at IS NULL
  AND EXISTS (
      SELECT 1 FROM org_invites i
      WHERE i.org_id = d.org_id AND i.email = lower(d.email) AND i.accepted_at IS NULL
  )
ON CONFLICT (org_id, owner_identity_id) WHERE system_kind = 'self' DO NOTHING;

INSERT INTO identity_groups (identity_id, group_id)
SELECT g.owner_identity_id, g.id
FROM groups g
JOIN identities d ON d.id = g.owner_identity_id
WHERE g.system_kind = 'self'
  AND d.external_id IS NULL
  AND EXISTS (
      SELECT 1 FROM org_invites i
      WHERE i.org_id = d.org_id AND i.email = lower(d.email) AND i.accepted_at IS NULL
  )
ON CONFLICT DO NOTHING;

-- 4. Admin invites → real org admin: Admins-group membership + the
--    `is_org_admin` fast-path flag, matching `set_is_org_admin`.
-- `archived_at IS NULL` matters here as much as in the INSERTs above: an
-- archived identity sharing the invited email must NOT be silently flagged
-- admin, or restoring it later would resurrect it with org-admin authority
-- nobody granted. (Step 1 deliberately treats an archived row as absent and
-- creates a fresh identity, so both can match this email.)
UPDATE identities d
SET is_org_admin = true
FROM org_invites i
WHERE i.org_id = d.org_id
  AND i.email = lower(d.email)
  AND i.accepted_at IS NULL
  AND i.role = 'admin'
  AND d.kind = 'user'
  AND d.external_id IS NULL
  AND d.archived_at IS NULL;

INSERT INTO identity_groups (identity_id, group_id)
SELECT d.id, g.id
FROM identities d
JOIN groups g ON g.org_id = d.org_id AND g.system_kind = 'admins'
JOIN org_invites i ON i.org_id = d.org_id AND i.email = lower(d.email)
WHERE d.kind = 'user'
  AND d.external_id IS NULL
  AND d.archived_at IS NULL
  AND i.accepted_at IS NULL
  AND i.role = 'admin'
ON CONFLICT DO NOTHING;

-- 5. The invite is now an identity. Drop the table.
DROP TABLE org_invites;
