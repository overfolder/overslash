-- Enrollment tokens: user-initiated flow.
-- Scoped to a specific pre-existing agent identity. Single-use.
CREATE TABLE enrollment_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    identity_id     UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    token_prefix    VARCHAR(16) NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    created_by      UUID REFERENCES identities(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_enrollment_tokens_prefix ON enrollment_tokens(token_prefix);

-- Pending enrollments: agent-initiated flow.
-- Everything is floating until a user approves via browser.
CREATE TABLE pending_enrollments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    suggested_name      TEXT NOT NULL,
    platform            TEXT,
    metadata            JSONB NOT NULL DEFAULT '{}',
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    approval_token      TEXT NOT NULL UNIQUE,
    poll_token_hash     TEXT NOT NULL,
    poll_token_prefix   VARCHAR(16) NOT NULL,
    -- filled on approval:
    org_id              UUID REFERENCES orgs(id),
    identity_id         UUID REFERENCES identities(id),
    api_key_hash        TEXT,
    api_key_prefix      VARCHAR(16),
    approved_by         UUID REFERENCES identities(id),
    final_name          TEXT,
    -- lifecycle:
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at         TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_pending_enrollments_poll_prefix ON pending_enrollments(poll_token_prefix);
CREATE INDEX idx_pending_enrollments_status ON pending_enrollments(status) WHERE status = 'pending';
