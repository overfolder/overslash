-- Rate limiting configuration per identity (SPEC.md §14)
-- Two-tier model: User bucket (shared by all agents) + optional identity caps.

CREATE TABLE rate_limits (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- Scope determines what this limit applies to:
    --   'org'          — org-wide default (identity_id=NULL, group_id=NULL)
    --   'group'        — group default    (identity_id=NULL, group_id=SET)
    --   'user'         — user budget      (identity_id=SET,  group_id=NULL)
    --   'identity_cap' — per-agent cap    (identity_id=SET,  group_id=NULL)
    identity_id UUID REFERENCES identities(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    scope TEXT NOT NULL CHECK (scope IN ('org', 'group', 'user', 'identity_cap')),
    max_requests INTEGER NOT NULL DEFAULT 1000,
    window_seconds INTEGER NOT NULL DEFAULT 60,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_rate_limits_org ON rate_limits(org_id);

-- One org default per org
CREATE UNIQUE INDEX idx_rate_limits_org_default
    ON rate_limits(org_id) WHERE scope = 'org';

-- One rate limit per group
CREATE UNIQUE INDEX idx_rate_limits_group
    ON rate_limits(org_id, group_id) WHERE scope = 'group';

-- One user budget per user identity
CREATE UNIQUE INDEX idx_rate_limits_user
    ON rate_limits(org_id, identity_id) WHERE scope = 'user';

-- One identity cap per identity
CREATE UNIQUE INDEX idx_rate_limits_identity_cap
    ON rate_limits(org_id, identity_id) WHERE scope = 'identity_cap';
