-- Multi-org makes the pre-040 "one user-kind identity per email globally"
-- rule incorrect: the same human can be a member of multiple orgs, with an
-- `identities` row per (org, user). The partial UNIQUE on identities.email
-- (migration 013) blocked that, so we drop it here.
--
-- Uniqueness of "one actor per human per org" is enforced by the partial
-- UNIQUE on (org_id, user_id) WHERE kind='user' added in migration 040. The
-- email column stays informational — we never key auth on it.
--
-- A weaker per-org UNIQUE (`(org_id, email)`) is tempting, but an org may
-- legitimately have two IdP identities that report the same email on first
-- sign-in (e.g., re-used test accounts). Skip it.

DROP INDEX IF EXISTS idx_identities_user_email;

-- Keep a plain (non-unique) index on email so admin UIs that filter by email
-- still have an index to use. The index was created by migration 013 with
-- UNIQUE; we can't ALTER it away, so drop + recreate as a plain index.
CREATE INDEX IF NOT EXISTS idx_identities_email_lookup
    ON identities (email)
    WHERE email IS NOT NULL;
