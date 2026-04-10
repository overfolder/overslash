-- Org settings for the three-tier template registry.
ALTER TABLE orgs
    ADD COLUMN allow_user_templates BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN global_templates_enabled BOOLEAN NOT NULL DEFAULT true;

-- When global_templates_enabled is false for an org, only global templates
-- listed here are visible to non-admin members of that org.
CREATE TABLE enabled_global_templates (
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    template_key TEXT NOT NULL,
    enabled_by   UUID REFERENCES identities(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, template_key)
);
