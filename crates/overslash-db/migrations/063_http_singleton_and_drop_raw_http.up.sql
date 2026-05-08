-- Migration 063: collapse Mode A into a real `http` service instance.
--
-- Before: raw HTTP access was gated by the `groups.allow_raw_http` boolean,
-- handled as a special case in `check_group_ceiling` (overslash-core).
-- After: every org has a system-managed `http` service_instances row, and
-- groups grant access to it via the standard `group_grants` mechanism. The
-- access level maps to verb risk (read = GET/HEAD/OPTIONS, write = + POST/
-- PUT/PATCH, admin = + DELETE) like any other HTTP service.
--
-- This migration is idempotent within a single orgs/groups snapshot. The
-- column drop at the bottom enforces the cutover.

-- 1. Create the org-level `http` system instance for every existing org.
INSERT INTO service_instances (org_id, name, template_source, template_key, status, is_system, owner_identity_id)
SELECT o.id, 'http', 'global', 'http', 'active', true, NULL
FROM orgs o
ON CONFLICT (org_id, name) WHERE owner_identity_id IS NULL DO NOTHING;

-- 2. For every group with `allow_raw_http = true`, mirror that as a grant on
--    its org's `http` instance with `access_level = 'admin'`. Today's flag
--    permits any verb, so admin (which permits delete/destructive too) is the
--    closest one-to-one mapping. Org admins can downgrade to `write` or
--    `read` afterwards.
INSERT INTO group_grants (group_id, service_instance_id, access_level)
SELECT g.id, si.id, 'admin'
FROM groups g
JOIN service_instances si
  ON si.org_id = g.org_id
 AND si.name = 'http'
 AND si.is_system = true
WHERE g.allow_raw_http = true
ON CONFLICT (group_id, service_instance_id) DO NOTHING;

-- 3. Drop the column. After this, all callers must read access via the
--    normal grants path.
ALTER TABLE groups DROP COLUMN allow_raw_http;
