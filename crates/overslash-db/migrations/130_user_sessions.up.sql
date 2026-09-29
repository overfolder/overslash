-- Server-side dashboard sessions (CASA 2.2.1, 2.2.2, 2.2.3).
--
-- The session cookie is still a signed JWT, but it now carries a `jti` that
-- names a row here, and every request checks that row is live. Logout, an
-- identity change, an admin removal and "terminate this session" all work by
-- stamping `revoked_at`; a JWT whose row is revoked, expired or missing is no
-- session at all, however valid its signature.
--
-- One row is one browser sign-in. Switching org re-scopes the same row
-- (`org_id` / `identity_id` follow the cookie) rather than minting another,
-- so the sessions list shows one entry per device, not one per org visited.
CREATE TABLE user_sessions (
    -- The JWT's `jti`.
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The human. Nullable only because a few legacy user identities still
    -- have no `users` row; such a session is listed nowhere but still
    -- revocable by identity.
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    -- What the cookie is currently scoped to. Deleting the identity deletes
    -- the row, and a missing row is a dead session.
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Coarse: refreshed at most every few minutes, on a cache miss.
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    -- Display-only, for the sessions list. Truncated by the API.
    user_agent TEXT,
    ip_address TEXT
);

-- "All of this user's live sessions" (the account page, terminate-all).
CREATE INDEX user_sessions_user_live_idx
    ON user_sessions (user_id) WHERE revoked_at IS NULL;
-- "All live sessions on these identities" (admin removal, archive).
CREATE INDEX user_sessions_identity_live_idx
    ON user_sessions (identity_id) WHERE revoked_at IS NULL;
-- Retention sweep.
CREATE INDEX user_sessions_expires_idx ON user_sessions (expires_at);
