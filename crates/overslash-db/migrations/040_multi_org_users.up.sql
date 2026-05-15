-- PR 1 of the multi-org rollout — see docs/design/multi_org_auth.md
-- Schema only + backfill. No behavior change; auth.rs still authenticates
-- against identities.external_id as before. PR 4 rewires login to use the
-- new users/memberships tables.

-- --------------------------------------------------------------------------
-- 1. users — one row per human, decoupled from any org
-- --------------------------------------------------------------------------
CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                   TEXT,
    display_name            TEXT,
    overslash_idp_provider  TEXT,
    overslash_idp_subject   TEXT,
    personal_org_id         UUID,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- email is informational (last value the IdP returned) and NOT unique.
-- Two different Google accounts that report the same email must produce
-- distinct rows. Uniqueness on email would also turn login-time collisions
-- into an account-existence oracle. Lookups at login are always by
-- (overslash_idp_provider, overslash_idp_subject) — see the partial unique
-- index below.
CREATE UNIQUE INDEX users_overslash_idp_unique
    ON users (overslash_idp_provider, overslash_idp_subject)
    WHERE overslash_idp_provider IS NOT NULL AND overslash_idp_subject IS NOT NULL;

CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_personal_org ON users (personal_org_id);

-- --------------------------------------------------------------------------
-- 2. user_org_memberships — links humans to orgs with a role
-- --------------------------------------------------------------------------
CREATE TABLE user_org_memberships (
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    role         TEXT NOT NULL,
    is_bootstrap BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, org_id),
    CONSTRAINT user_org_memberships_role_check
        CHECK (role IN ('admin', 'member'))
);

CREATE INDEX idx_memberships_org ON user_org_memberships (org_id);

-- --------------------------------------------------------------------------
-- 3. orgs.is_personal — flags the auto-created single-member personal org
-- --------------------------------------------------------------------------
ALTER TABLE orgs ADD COLUMN is_personal BOOLEAN NOT NULL DEFAULT false;

-- --------------------------------------------------------------------------
-- 4. identities.user_id — links the per-org "actor" row to its human
--    FK added AFTER backfill so we can populate identities.user_id with a
--    freshly-generated UUID and insert the matching users row in a later step.
-- --------------------------------------------------------------------------
ALTER TABLE identities ADD COLUMN user_id UUID;

-- --------------------------------------------------------------------------
-- 5. Backfill
--    identities.email is globally unique WHERE kind='user' AND email IS NOT NULL
--    (existing partial unique index), so one identity per email for user-kind
--    rows with email. Users without email (rare, legacy) get 1:1 mapped to a
--    fresh users row keyed by the same UUID we stamp onto identities.user_id.
-- --------------------------------------------------------------------------

-- 5a. One users row per distinct user-kind identity WITH email.
INSERT INTO users (id, email, display_name, created_at, updated_at)
SELECT gen_random_uuid(), email, name, created_at, updated_at
FROM identities
WHERE kind = 'user' AND email IS NOT NULL;

-- 5b. Link identities.user_id for email-bearing rows via the (globally unique) email.
UPDATE identities i
SET user_id = u.id
FROM users u
WHERE i.kind = 'user'
  AND i.email IS NOT NULL
  AND i.email = u.email;

-- 5c. For user-kind identities with NULL email, stamp a fresh UUID into
--     identities.user_id first, then insert a matching users row. This is
--     the only safe way to preserve a 1:1 mapping for rows we can't key on
--     email.
UPDATE identities
SET user_id = gen_random_uuid()
WHERE kind = 'user' AND email IS NULL AND user_id IS NULL;

INSERT INTO users (id, email, display_name, created_at, updated_at)
SELECT user_id, NULL, name, created_at, updated_at
FROM identities
WHERE kind = 'user' AND email IS NULL AND user_id IS NOT NULL;

-- 5d. Now that every user-kind identity has a user_id pointing at a real row,
--     install the FK. ON DELETE SET NULL so deleting a users row leaves the
--     identity row intact (identity is the gateway's unit of permission;
--     orphaning it signals "this used to be a human, no longer claimed").
ALTER TABLE identities
    ADD CONSTRAINT identities_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX idx_identities_user ON identities (user_id);

-- 5e. One membership per user-kind identity. Admin role derived from the
--     existing is_org_admin flag; is_bootstrap stays false (bootstraps are
--     only created by POST /v1/orgs in PR 4).
INSERT INTO user_org_memberships (user_id, org_id, role, is_bootstrap, created_at)
SELECT i.user_id,
       i.org_id,
       CASE WHEN i.is_org_admin THEN 'admin' ELSE 'member' END,
       false,
       i.created_at
FROM identities i
WHERE i.kind = 'user' AND i.user_id IS NOT NULL;

-- --------------------------------------------------------------------------
-- 6. personal_org_id FK on users — must reference orgs, which exists
-- --------------------------------------------------------------------------
ALTER TABLE users
    ADD CONSTRAINT users_personal_org_id_fkey
    FOREIGN KEY (personal_org_id) REFERENCES orgs(id) ON DELETE SET NULL;
