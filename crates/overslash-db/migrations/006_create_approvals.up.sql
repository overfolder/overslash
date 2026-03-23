CREATE TABLE approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    action_summary TEXT NOT NULL,
    action_detail JSONB,
    permission_keys TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'allowed', 'denied', 'expired')),
    resolved_at TIMESTAMPTZ,
    resolved_by TEXT,
    remember BOOLEAN NOT NULL DEFAULT false,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_approvals_org_status ON approvals(org_id, status);
CREATE INDEX idx_approvals_identity ON approvals(identity_id);
CREATE INDEX idx_approvals_expires ON approvals(expires_at) WHERE status = 'pending';
