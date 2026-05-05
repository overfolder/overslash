-- Permission split: `manage_connections` → `manage_connections_own`
-- (per docs/design/agent-self-management.md §1, mirroring the
--  `manage_services_own` / `manage_templates_own` splits in 058 / 246).
--
-- The new `create_connection` platform action anchors on
-- `manage_connections_own`. Existing deployments have user-written
-- permission rules with the old `overslash:manage_connections:*` anchor;
-- without this migration those rules would no-op against the renamed
-- action and agents would silently lose the ability to mint OAuth
-- connections they previously had permission for.

-- `'overslash:manage_connections:'` is 29 chars (1..29 inclusive of the
-- colon), so the suffix starts at position 30.
UPDATE permission_rules
SET action_pattern = 'overslash:manage_connections_own:' || substring(action_pattern from 30)
WHERE action_pattern LIKE 'overslash:manage_connections:%';
