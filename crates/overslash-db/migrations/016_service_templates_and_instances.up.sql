-- Service templates: org-level and user-level custom templates stored in DB.
-- Global templates remain as shipped YAML files loaded into the in-memory registry.
CREATE TABLE service_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    owner_identity_id UUID REFERENCES identities(id) ON DELETE CASCADE,  -- NULL = org-level, non-NULL = user-level
    key             TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL DEFAULT '',
    hosts           TEXT[] NOT NULL DEFAULT '{}',
    auth            JSONB NOT NULL DEFAULT '[]',
    actions         JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Org-level templates: unique key per org
CREATE UNIQUE INDEX idx_service_templates_org_key
    ON service_templates(org_id, key) WHERE owner_identity_id IS NULL;

-- User-level templates: unique key per user within an org
CREATE UNIQUE INDEX idx_service_templates_user_key
    ON service_templates(org_id, owner_identity_id, key) WHERE owner_identity_id IS NOT NULL;

CREATE INDEX idx_service_templates_org ON service_templates(org_id);


-- Service instances: named instantiations of templates with bound credentials and lifecycle.
CREATE TABLE service_instances (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    owner_identity_id UUID REFERENCES identities(id) ON DELETE CASCADE,  -- NULL = org service, non-NULL = user service
    name            TEXT NOT NULL,
    template_source TEXT NOT NULL CHECK (template_source IN ('global', 'org', 'user')),
    template_key    TEXT NOT NULL,
    template_id     UUID REFERENCES service_templates(id) ON DELETE SET NULL,  -- NULL for global templates
    connection_id   UUID REFERENCES connections(id) ON DELETE SET NULL,
    secret_name     TEXT,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft', 'active', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Org-level instances: unique name per org
CREATE UNIQUE INDEX idx_service_instances_org_name
    ON service_instances(org_id, name) WHERE owner_identity_id IS NULL;

-- User-level instances: unique name per user within an org
CREATE UNIQUE INDEX idx_service_instances_user_name
    ON service_instances(org_id, owner_identity_id, name) WHERE owner_identity_id IS NOT NULL;

CREATE INDEX idx_service_instances_org ON service_instances(org_id);
CREATE INDEX idx_service_instances_owner ON service_instances(owner_identity_id);
