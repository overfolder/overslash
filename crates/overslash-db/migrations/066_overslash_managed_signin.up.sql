-- Opt-in: corp orgs can accept Overslash-managed sign-in (env-var OAuth
-- apps like GOOGLE_AUTH_CLIENT_ID/SECRET) instead of registering their
-- own OAuth client. Membership is decoupled from authentication: the
-- email claim from a global IdP can no longer silently admit a stranger
-- — admission is gated by an admin-curated `org_invites` allowlist.
--
-- The column is DEFAULT false here so existing orgs are unaffected on
-- migration; new-org creation flips it to true at the handler layer
-- (`POST /v1/orgs` and the free-unlimited entry).

ALTER TABLE orgs
    ADD COLUMN allow_overslash_managed_signin BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE org_invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Lower-cased at the application boundary; the CHECK keeps DB-direct
    -- inserts honest. Lookup is `WHERE email = lower($1)`.
    email       TEXT NOT NULL,
    role        TEXT NOT NULL,
    invited_by  UUID REFERENCES identities(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at TIMESTAMPTZ,
    accepted_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT org_invites_role_check CHECK (role IN ('admin', 'member')),
    CONSTRAINT org_invites_email_lower CHECK (email = lower(email))
);

-- At most one pending invite per (org, email). Accepted invites are kept
-- for audit history and don't block re-invite of the same email if the
-- admin first revokes & re-creates.
CREATE UNIQUE INDEX org_invites_one_pending_per_email
    ON org_invites (org_id, email)
    WHERE accepted_at IS NULL;

-- Hot path on login: "is there a pending invite for this verified email
-- in this org?". Org-scoped query but the email index alone is cheap.
CREATE INDEX org_invites_by_org_email ON org_invites (org_id, email);
