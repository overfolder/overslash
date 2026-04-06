-- Org-level ACL: system groups + overslash service instance per org.
-- ACL is enforced via group grants on the "overslash" service, not a separate role system.

ALTER TABLE groups ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE service_instances ADD COLUMN is_system BOOLEAN NOT NULL DEFAULT false;

-- Bootstrap system assets for every existing org.
-- New orgs get bootstrapped at creation time in application code.
DO $$
DECLARE
    r RECORD;
    svc_id UUID;
    everyone_id UUID;
    admins_id UUID;
    first_user_id UUID;
BEGIN
    FOR r IN SELECT id FROM orgs LOOP
        -- Create the overslash service instance
        INSERT INTO service_instances (org_id, name, template_source, template_key, status, is_system)
        VALUES (r.id, 'overslash', 'global', 'overslash', 'active', true)
        ON CONFLICT DO NOTHING
        RETURNING id INTO svc_id;

        -- If already existed (conflict), look it up
        IF svc_id IS NULL THEN
            SELECT id INTO svc_id FROM service_instances
            WHERE org_id = r.id AND name = 'overslash' AND is_system = true;
        END IF;

        -- Create Everyone group (allow_raw_http = true for backward compat)
        INSERT INTO groups (org_id, name, description, is_system, allow_raw_http)
        VALUES (r.id, 'Everyone', 'All users in this organization', true, true)
        ON CONFLICT (org_id, name) DO UPDATE SET is_system = true, allow_raw_http = true
        RETURNING id INTO everyone_id;

        -- Create Admins group
        INSERT INTO groups (org_id, name, description, is_system, allow_raw_http)
        VALUES (r.id, 'Admins', 'Organization administrators', true, true)
        ON CONFLICT (org_id, name) DO UPDATE SET is_system = true, allow_raw_http = true
        RETURNING id INTO admins_id;

        -- Grant Everyone write access to overslash
        IF svc_id IS NOT NULL THEN
            INSERT INTO group_grants (group_id, service_instance_id, access_level)
            VALUES (everyone_id, svc_id, 'write')
            ON CONFLICT (group_id, service_instance_id) DO NOTHING;

            -- Grant Admins admin access to overslash
            INSERT INTO group_grants (group_id, service_instance_id, access_level)
            VALUES (admins_id, svc_id, 'admin')
            ON CONFLICT (group_id, service_instance_id) DO NOTHING;
        END IF;

        -- Add all existing users to the Everyone group
        INSERT INTO identity_groups (identity_id, group_id)
        SELECT id, everyone_id FROM identities
        WHERE org_id = r.id AND kind = 'user'
        ON CONFLICT DO NOTHING;

        -- Add the earliest user as admin
        SELECT id INTO first_user_id FROM identities
        WHERE org_id = r.id AND kind = 'user'
        ORDER BY created_at ASC LIMIT 1;

        IF first_user_id IS NOT NULL THEN
            INSERT INTO identity_groups (identity_id, group_id)
            VALUES (first_user_id, admins_id)
            ON CONFLICT DO NOTHING;
        END IF;
    END LOOP;
END $$;
