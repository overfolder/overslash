-- ACL tables for org-level role-based access control

CREATE TABLE acl_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_builtin BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, slug)
);
CREATE INDEX idx_acl_roles_org ON acl_roles(org_id);

CREATE TABLE acl_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES acl_roles(id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL CHECK (resource_type IN (
        'services', 'connections', 'secrets', 'agents', 'approvals',
        'audit_logs', 'webhooks', 'org_settings', 'acl'
    )),
    action TEXT NOT NULL CHECK (action IN ('read', 'write', 'delete', 'manage')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(role_id, resource_type, action)
);
CREATE INDEX idx_acl_grants_role ON acl_grants(role_id);

CREATE TABLE acl_role_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES acl_roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES identities(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(identity_id, role_id)
);
CREATE INDEX idx_acl_assignments_identity ON acl_role_assignments(identity_id);
CREATE INDEX idx_acl_assignments_org ON acl_role_assignments(org_id);

-- Seed built-in roles for all existing orgs
DO $$
DECLARE
    org RECORD;
    admin_role_id UUID;
    member_role_id UUID;
    readonly_role_id UUID;
    first_user_id UUID;
BEGIN
    FOR org IN SELECT id FROM orgs LOOP
        -- Create built-in roles
        INSERT INTO acl_roles (org_id, name, slug, description, is_builtin)
        VALUES (org.id, 'Org Admin', 'org-admin', 'Full access to all org resources and settings', true)
        ON CONFLICT (org_id, slug) DO NOTHING
        RETURNING id INTO admin_role_id;

        INSERT INTO acl_roles (org_id, name, slug, description, is_builtin)
        VALUES (org.id, 'Member', 'member', 'Read and write access to core resources', true)
        ON CONFLICT (org_id, slug) DO NOTHING
        RETURNING id INTO member_role_id;

        INSERT INTO acl_roles (org_id, name, slug, description, is_builtin)
        VALUES (org.id, 'Read Only', 'read-only', 'Read-only access to most resources', true)
        ON CONFLICT (org_id, slug) DO NOTHING
        RETURNING id INTO readonly_role_id;

        -- If roles already existed, fetch their IDs
        IF admin_role_id IS NULL THEN
            SELECT id INTO admin_role_id FROM acl_roles WHERE org_id = org.id AND slug = 'org-admin';
        END IF;
        IF member_role_id IS NULL THEN
            SELECT id INTO member_role_id FROM acl_roles WHERE org_id = org.id AND slug = 'member';
        END IF;
        IF readonly_role_id IS NULL THEN
            SELECT id INTO readonly_role_id FROM acl_roles WHERE org_id = org.id AND slug = 'read-only';
        END IF;

        -- Org-admin grants: manage on all resource types
        INSERT INTO acl_grants (role_id, resource_type, action)
        SELECT admin_role_id, rt, 'manage'
        FROM unnest(ARRAY['services','connections','secrets','agents','approvals','audit_logs','webhooks','org_settings','acl']) AS rt
        ON CONFLICT DO NOTHING;

        -- Member grants: read+write on core resources, read on audit/webhooks
        INSERT INTO acl_grants (role_id, resource_type, action)
        VALUES
            (member_role_id, 'services', 'read'),
            (member_role_id, 'services', 'write'),
            (member_role_id, 'connections', 'read'),
            (member_role_id, 'connections', 'write'),
            (member_role_id, 'secrets', 'read'),
            (member_role_id, 'secrets', 'write'),
            (member_role_id, 'agents', 'read'),
            (member_role_id, 'agents', 'write'),
            (member_role_id, 'approvals', 'read'),
            (member_role_id, 'approvals', 'write'),
            (member_role_id, 'audit_logs', 'read'),
            (member_role_id, 'webhooks', 'read')
        ON CONFLICT DO NOTHING;

        -- Read-only grants: read on most resources
        INSERT INTO acl_grants (role_id, resource_type, action)
        SELECT readonly_role_id, rt, 'read'
        FROM unnest(ARRAY['services','connections','secrets','agents','approvals','audit_logs','webhooks']) AS rt
        ON CONFLICT DO NOTHING;

        -- Assign org-admin to the first user identity in the org
        SELECT id INTO first_user_id
        FROM identities
        WHERE org_id = org.id AND kind = 'user'
        ORDER BY created_at ASC
        LIMIT 1;

        IF first_user_id IS NOT NULL THEN
            INSERT INTO acl_role_assignments (org_id, identity_id, role_id)
            VALUES (org.id, first_user_id, admin_role_id)
            ON CONFLICT DO NOTHING;
        END IF;
    END LOOP;
END $$;
