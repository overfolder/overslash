-- Groups: Layer 1 permission ceiling (SPEC.md §5)
-- Coarse-grained ceilings managed by org-admins.
-- A request exceeding the group ceiling is denied outright — no approval can override it.

CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    allow_raw_http BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, name)
);

CREATE INDEX idx_groups_org ON groups(org_id);

CREATE TABLE group_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    service_instance_id UUID NOT NULL REFERENCES service_instances(id) ON DELETE CASCADE,
    access_level TEXT NOT NULL CHECK (access_level IN ('read', 'write', 'admin')),
    auto_approve_reads BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(group_id, service_instance_id)
);

CREATE INDEX idx_group_grants_group ON group_grants(group_id);
CREATE INDEX idx_group_grants_service ON group_grants(service_instance_id);

CREATE TABLE identity_groups (
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (identity_id, group_id)
);

CREATE INDEX idx_identity_groups_identity ON identity_groups(identity_id);
CREATE INDEX idx_identity_groups_group ON identity_groups(group_id);
